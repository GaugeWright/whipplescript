# Runtime & operations

This page gives the events after a workflow compiles. The page gives the
location of the state, the movement of an instance and an effect through their
lifecycles, the method that shows a failure, and the method to operate an
instance that runs.

## Runtime loops

The runtime keeps the deterministic progress separate from the execution by a
provider:

| Loop | Responsibility |
| --- | --- |
| starter | Makes an instance and seeds the input facts and events. |
| stepper | Evaluates the ready rules. Commits the facts, the effects, and the dependencies atomically. |
| worker | Claims the ready effects, runs the providers under a lease, and records the completions. |
| projection | Keeps the current views on the event log. The views are the facts, the effects, the status, and the traces. |

The `step` command never executes a provider. The `worker` command never makes
policy. The `run` command composes the loops for convenience on your machine.
The `run` command does not change the boundaries.

### Concurrent effect execution

A worker pass executes its ready set of effects concurrently. The pass uses a
thread pool with a limit. The members of the ready set are independent of each
other, because an effect with a dependency is not claimable until its dependency
gets to a terminal. The durable lease and the idempotency of each row give
exactly-once behavior, also under concurrency. The applicable invariant is
`AtMostOneRunExecutingEffect` in `models/tla/ControlPlaneLifecycle.tla`.

Thus a fan-out of agent turns or of `coerce` calls runs in parallel and not one
at a time. Thus `agent X { capacity N }` also has a true meaning at run time. A
worker starts a maximum of `N` turns of an agent at the same time. The worker
defers the other turns to a later pass.

The `WHIPPLESCRIPT_WORKER_CONCURRENCY` variable sets the limit for each pass.
The default follows the quantity of the available CPUs, with a cap. Set the
variable to `1` for a pass that is fully serial.

Each effect runs synchronously on its own thread of the pool. Whip is not
async. WAL mode and a busy timeout let the writes to the store of each effect
exist together safely. The slow I/O of a provider runs outside each transaction.
To scale further, run more worker processes against the same store.

## The store

The state is in a SQLite file. The default file is
`.whipplescript/store.sqlite`. Select a file for each environment explicitly.
Use the `--store <path>` flag or the `WHIPPLESCRIPT_STORE` environment
variable. Each command that touches an instance must use the store that made the
instance.

The store holds the versions of the programs, the instances, the append-only
event log, and the projections on that log. The projections are the facts, the
effects and their dependencies, the runs of the providers, the leases, the
invocations of the workflows, the items in the inbox, the evidence, the
artifacts, and the capabilities, profiles, packages, and providers that the
system registered. The event log is the source of truth. The system can rebuild
each other item from the log.

## Cloud runtime (Cloudflare Durable Object) and deploy

The native SQLite runtime above is one substrate. The same workflow also runs
with no change on the edge. The full core of the evaluation executes in a
**Cloudflare Durable Object** wasm isolate. The isolate is sans-IO. Its only
async primitive is `fetch`. Thus each effect that uses HTTP is a step machine
that can resume. Such a machine survives the eviction of the isolate and
continues from its position.

The host of the DO runs the *same* scheduler of instances that you run on your
machine. The scheduler runs over the synchronous SQLite of the Durable Object.
This is a full port of the stores of the runtime, the coordination, and the work
items. A timer and a deadline fire through a DO **alarm** and not on a worker
pass. The credentials of a provider come from the DO **secrets** and not from
the credential store on your machine.

The runtime on the edge has the same features as the native operation:

- A `file.*` effect runs against a file plane that the DO owns. There is no file
  system on the host.
- The `whip checkpoint` command and the `whip restore` command operate as
  commands of an operator on a deployed instance. The behavior is exactly the
  behavior on a native store. Refer to
  [Restoring to a prior point](#restoring-to-a-prior-point-checkpoint-restore).
- An agent turn runs a true set of tools in the isolate, against the storage of
  the DO. The tools are read, write, edit, ls, find, grep, recall, and the todo
  items of the work tracker. There is no file system and no subprocess.

### Deploying with `whip deploy`

The `whip deploy` command deploys a workflow to the edge in one operation. The
command deploys the workflow to a Worker and its Durable Object.

```sh
whip deploy [--worker-dir <path>] [--name <worker>] [--dry-run] [--skip-build] [--set-secrets]
```

Use the `--dry-run` flag to see the build and the upload before you publish
them. Use the `--skip-build` flag to use a wasm artifact that exists. Use the
`--set-secrets` flag to send the credentials of a provider into the secrets of
the DO as part of the deploy operation.

### Provider credentials on the edge: two realizations

A deployed placement realizes an admitted binding of a provider in one of two
methods (DR-0042).

The **`worker-secret`** method is the transitional form. A named secret of the
DO holds the key.

The **`model-broker`** method is the form with no secret. The isolate never
holds a key of a provider. WhippleScript first admits the turn. The
`whipplescript.model-egress.v1` protocol then carries the admitted request to an
authenticated broker on the host. The request has the URL that whip constructed,
the headers that are not for authentication, the body, the key for idempotency,
and an opaque *reference* to a credential. The broker injects the credential of
the provider immediately before the egress operation and returns the response.
The broker never constructs a prompt, never selects a model, never parses a
reply, and never makes evidence. WhippleScript continues to own each of these
operations. The broker holds the secret only.

In the two methods, the system selects the realization only when the binding
matches the admitted identifier of the binding and the reference to the
credential exactly.

### The compute plane (`whip executor`)

The `whip executor` command runs a **Class-A** sidecar for computation. The
runtime calls the sidecar over a `whip-executor/1` protocol.

```sh
whip executor [--bind <addr:port>]   # Class-A exec sidecar; default 127.0.0.1:8080
```

The sidecar authenticates each request with a bearer token from the
`WHIP_EXECUTOR_TOKEN` variable. The comparison uses a constant time. The sidecar
refuses a call that is not on the loopback interface and that has no token. A
Class-B path with a container for each turn also exists.

**To enable the compute plane in production, do a follow-on step of the
configuration.** The plane is not on by default. A workflow deploys and runs
without the plane. Connect the compute plane separately when you need it.

## Instance lifecycle

```text
running -> paused -> running        (pause / resume)
running -> completed                (a rule ran `complete`)
running -> failed                   (a rule ran `fail`)
running -> cancelled                (operator ran `cancel`)
```

The `completed`, `failed`, and `cancelled` states are terminal. The instance
rejects each subsequent commit of a rule and each subsequent transition of the
lifecycle. A cancel operation is an action of an operator. A cancel operation is
different from a `fail` statement of a workflow. There is no syntax in the
source for a cancel operation.

## Effects, runs, and leases

An *effect* is a durable request for external work. A *run* is one attempt of a
provider at an effect. A *lease* prevents a second worker from a claim on an
attempt that runs.

```text
queued -> running -> completed | failed | timed_out | cancelled
queued -> blocked_by_dependency | blocked_by_capacity
        | blocked_by_capability | blocked_by_profile
queued -> blocked            (provider binding unavailable; recoverable)
```

A **blocked** effect can recover. A blocked effect is not terminal. A later
worker pass runs the effect after the block goes away.

The system persists a gate of a policy at the moment when the scheduler first
observes the gate. The gates are `blocked_by_capability` and
`blocked_by_profile`. The status and the reason of the effect change
immediately. An example reason is `` profile `default` is not registered ``. The
system records an `effect.blocked` event. The `whip run --wait` command lists
the blocked effects in the line that reports the idle state. The system
evaluates the gate again on each pass. Thus a registration of the absent profile
or capability removes the block, and you do not put the effect in the queue
manually.

The system finds some failures of a binding of a provider **before** the
execution by the provider. The sidecar of the provider cannot start, or a
configuration of a provider that is present has no reference to a necessary
credential. In these conditions, the system blocks the effect and does not fail
the effect. Thus a correction to the binding lets the run continue, and you do
not trigger the run again manually.

Each blocked effect carries a reason with a category. The `whip effects` command
and the `whip status` command show the reason as
`policy_block: { category, detail }`. The `category` value is one of
`capability`, `profile`, `capacity`, or `dependency`, which are the categories
at the time of the schedule operation. As an alternative, the value is
`provider_config`, `credentials`, `enforcement`, or `provider_health`, which are
the categories at the time of the binding. The detail never contains a secret
value.

The system records a failure of a provider as the state of an effect and a run,
as events, and as evidence. Such a failure does **not** fail the workflow. The
rules decide the policy: a retry, an escalation, no operation, or a `fail`
statement. This behavior is the central operational property. An instance with
ten failed runs of a provider is still in the `running` state, until a rule or
an operator changes the state.

| Outcome | Recorded as | Instance state |
| --- | --- | --- |
| A run of a provider failed or timed out. | The terminal state of the effect and the run, events, and evidence. | The state does not change until a rule reacts. |
| A rule executed a `fail ... { ... }` statement. | A `workflow.failed` event and a terminal payload. | `failed` |
| An operator ran a `cancel` command. | An event of a transition. | `cancelled` |

An adapter of a provider captures true diagnostics as evidence. The diagnostics
are the exit codes, extracts of stderr, the errors of an SDK, the reasons for a
timeout, the paths of the artifacts, and the identifiers for correlation. The
system never persists a secret.

## Inspecting an instance

```sh
whip --store <store> instances
whip --store <store> status      <instance>
whip --store <store> log         <instance>
whip --store <store> facts       <instance>
whip --store <store> effects     <instance>
whip --store <store> runs        <instance>
whip --store <store> diagnostics <instance>
whip --store <store> --json evidence instance <instance>
whip --store <store> --json trace <instance> --check
```

When an effect did not run, use this list in sequence. Use `effects` for the
status and the `policy_block_reason` value. Use `runs` for the attempts of the
provider. Then use `diagnostics` and `evidence`. Then use `trace --check` for
the conformance of the lifecycle. Add the `--json` flag to any of these
commands for output that a machine can read.

## Operating an instance

```sh
whip --store <store> pause  <instance>     # block new provider starts
whip --store <store> resume <instance>
whip --store <store> cancel <instance>     # terminal
whip --store <store> retry  <instance> <effect>
```

The `retry` command moves an effect that failed or that timed out, and that is
eligible, back to the `queued` state.

The `recover` command reconciles the runs of a native provider that stopped. The
command uses the evidence that the system persisted after a crash. Refer to
[providers & packages](providers.md).

Sometimes a run started but stopped before the system recorded a terminal or
evidence, and the provider has no idempotent method to query the result. In this
condition, the recovery resolves the run to an **`uncertain` terminal of the
run**. The effect becomes `failed`, and thus the `fails` branches of the rules
react. The run carries the `runtime.recovery_uncertain` diagnostic. That
diagnostic states that the system could not confirm that the external side
effect occurred. The recovery never runs such an effect again silently. The
`retry` command is an explicit decision of an operator.

### Restoring to a prior point (checkpoint / restore)

The `checkpoint` command and the `restore` command rewind the *context* of an
instance to an earlier point. The commands do not rewind one effect only.

```sh
whip --store <store> checkpoint <instance>              # capture a cut of head
whip --store <store> checkpoint <instance> --cut-id <id>
whip --store <store> restore    <instance> <cut-id>     # rewind to that cut
```

A checkpoint captures a coherent *cut* across three planes at the same time. The
planes are the state of the files, the transcript of the agent, and the position
in the event log. The `restore` command rewinds the three planes to a named cut
as one operation, and the command checks the coherence. Thus the planes never
move apart. The command does a full reconcile operation. The command also makes
an automatic checkpoint of the head first. Thus you can recover the state before
the restore operation.

The rewind operation permits append only. The command records a
`context.restored` marker. Each subsequent read folds that marker. The command
does not delete history. This behavior agrees with the rule that the event log
is the source of truth. Add the `--json` flag for output that a machine can
read. The checkpoint operation and the restore operation use native file I/O.

## Child workflows

An `invoke Workflow { ... } as child` statement makes a durable child instance
with its own event log. The invocation effect of the parent resolves from the
terminal state of the child. The child supplies the declared output payload on a
completion, or the declared failure payload on a failure. The parent never reads
a fact that is local to the child.

## Revising a running instance

The `whip revise` command changes an instance that is not terminal to a new
version of the program. The command first checks the compatibility. Always use a
preview first:

```sh
whip --store <store> revise <instance> candidate.whip --root Workflow --dry-run
whip --store <store> revise <instance> candidate.whip --root Workflow --cancel keep
```

A revision permits append only. The runtime records an event for the
activation, a new epoch of the revision, and the diagnostics. An effect that
exists keeps its original version of the program. A subsequent commit uses the
new version. The `--cancel` policy controls the work of the old version:

| Policy | Effect on the work of the old version |
| --- | --- |
| `keep` | The work stays claimable and able to run. |
| `queued` | The command cancels each effect that is in the queue, blocked, or claimable. The cancel operation is terminal. |
| `running` | The command does the operation of the `queued` policy. The command also requests a cancel operation for each effect that runs. |

A cancel operation under the `running` policy is a request and not a result. The
provider still records the terminal outcome through the usual lifecycle of an
effect.

In v0, a revision is limited to the same root workflow. An internal tracker records a change of the root and a migration of the facts
that breaks the schema.

## Capturing an incident

Before you repair or delete the state of the runtime, capture the JSON views:

```sh
for cmd in status log facts effects runs evidence; do
  whip --store <store> --json $cmd <instance> > incident-$cmd.json
done
whip --store <store> --json trace <instance> --check > incident-trace.json
```

For a problem with a provider, also keep the artifacts and the names of the
configurations of the providers. Never keep the value of a credential.

Sometimes you want a point that you can rewind to before you act, and not only a
snapshot in JSON. In that condition, first make a
[checkpoint](#restoring-to-a-prior-point-checkpoint-restore) of the instance. The
`restore` command can then return the three planes to that cut.
