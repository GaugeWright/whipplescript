# Runtimes: native & the edge

This last chapter of the manual gives the machinery that supported each command
from `whip run` in chapter 1. The goal is the *model*. The chapter gives the
parts of the runtime and the reason that a program transfers between the
placements with no change. The operational reference gives each flag and each
table of failures. That reference is
[Runtime & operations](../runtime-operations.md).

## Four loops on one record

Each operation of the runtime divides into four loops. Each loop has strict
responsibilities:

| Loop | Responsibility |
| --- | --- |
| starter | Makes an instance. Seeds the input facts and the events. |
| stepper | Evaluates the ready rules. Commits the facts, the effects, and the dependencies atomically. |
| worker | Claims the ready effects. Runs the providers under a lease. Records the outcomes. |
| projection | Keeps the views for queries on the log. The views are `facts`, `effects`, `status`, and the traces. |

One boundary is important: **the `step` operation never executes a provider,
and the worker never makes policy.** The stepper is the deterministic half. For
the same record, the stepper commits the same rules. The worker is the half
that is not deterministic. The lifecycle of an effect from chapter 5 isolates
the worker. The `whip run` command only composes the loops for convenience on
your machine. Nothing changes when you run the loops as separate processes. In
production, the loops run as separate processes. Thus a view from chapter 30
can observe the loops from a third process with no cooperation from the other
processes.

A worker pass executes its ready set concurrently on a thread pool with a
limit. By construction, the members of the ready set are independent of each
other. An effect with a dependency is not claimable until its upstream effect
settles. The durable lease and the idempotency of each row give exactly-once
behavior, also under concurrency. The TLA+ model of the lifecycle holds this
invariant. Thus the invariant is not only in the tests. This machinery makes
`capacity N` on an agent true, and it makes a fan-out truly parallel.

## The native store

On your machine, the record is a SQLite file. The default file is
`.whipplescript/store.sqlite`. Select a different file with the `--store` flag
or the `WHIPPLESCRIPT_STORE` variable. The append-only event log is the source
of truth. Each other table is a projection. The tables are the facts, the
effects, the runs, the leases, the evidence, and each table that you queried
through the panel in chapter 30. The system can rebuild each projection from
the log.

Two operational results follow, and you already used them. First, you must
point each command at the store that made its instance. Second, a workflow is
portable as a file. The checkpoint bundles in chapter 21 make this property
explicit.

## The same program, on the edge

The second placement runs the *same evaluation core*. The core runs in a wasm
isolate in a Cloudflare **Durable Object**. The port is total. The port is not a
second implementation. The DO host runs the same scheduler of instances on the
synchronous SQLite of the Durable Object. The system replaces the parts that
depend on the placement at the edges. A timer fires through a DO **alarm** and
not on a worker pass. The credentials of a provider come from DO **secrets**.
In the `model-broker` realization, which uses no secrets, the credentials come
from a broker on the host. The broker injects the key only at the moment of the
egress operation. Thus the isolate never holds the key. The operations guide
gives the two methods. A `file.*` effect runs against a file plane that the DO
owns. There is no file system on the host.

The isolate is **sans-IO**. Its only async primitive is `fetch`. Thus each
effect that uses HTTP is a step machine that can resume. Such a machine
survives the eviction of the isolate and continues from its position. This
property is not a small detail of the implementation. This property gives a
long agent turn or a slow call to a provider on the edge the same durability
that chapter 5 promised on your machine. The record advances by committed
steps. The record never advances by a continuation in memory that an eviction
can remove.

The parity of the features is deliberate, and tests confirm the parity. A
checkpoint operation and a restore operation are operator commands on a
deployed instance. An agent turn gets a true set of tools in the isolate. The
tools are read, write, edit, ls, find, grep, recall, and the todo items of a
tracker. The virtual bash tool from chapter 33 is also available. The tools
operate on the DO storage. The two placements share the conformance models.
Thus this manual taught thirty-three chapters and did not give your placement.
The semantics truly do not depend on the placement.

## The `whip deploy` command and the compute plane

One command deploys a workflow:

```sh
whip deploy --dry-run
```

The `deploy` command builds the wasm artifact. The command assembles the Worker
and its Durable Object. The command then publishes the result. The `--dry-run`
flag gives a preview and publishes nothing. The `--skip-build` flag uses an
artifact that exists. The `--set-secrets` flag sends the references to the
provider credentials into the DO secrets as part of the deploy operation.

One item does *not* go with the deploy operation by default: the true execution
of a subprocess. On a deployed instance, the hosted scripts from chapter 19 need
the **compute plane**. The compute plane is the `whip executor` command. The
executor is a Class-A sidecar. The sidecar speaks the `whip-executor/1`
protocol. The sidecar authenticates with a bearer token and has a guard on the
loopback interface. To enable the executor in production, do a deliberate
follow-on step of the configuration. A workflow deploys and runs without the
executor. The division in chapter 33 gives the tools that each side serves. The
virtual bash tool and the file tools are in the isolate. The true scripts are
behind the executor.

## How to select a placement

- Use the **native** placement when the workflow belongs to a machine. Local
  development, an agent that writes to a repository, and each workflow that
  depends on a hosted script or on the OS are examples.
- Use the **edge** placement when the workflow belongs to no machine. A service
  with a long life, coordination that ingress drives, and each workflow that
  must continue after a person closes a laptop are examples. A webhook from
  chapter 17 terminates naturally at a Worker.

The two placements obey the record identically. Thus this decision is late and
reversible. Develop on the native placement. Deploy the same source. If it is
necessary, move the history of an instance with the bundles from chapter 21.

## The end

This is the full system. A workflow is a durable record. Rules advance the
record deterministically. An effect isolates the external world. An agent is an
effect with authority. Governance puts labels on the flows. Evidence measures
the improvements. The runtime is four loops that keep one honest log. This is
true for the two runtimes. This manual taught the idioms. The
[language reference](../language-reference.md) states the grammar. This manual
taught the guarantees. The [Guarantees](../guarantees.md) page connects the
guarantees to models that a machine checks. Now write a workflow that runs for
a month.
