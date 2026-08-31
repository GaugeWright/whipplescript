# Troubleshooting

This page gives the usual problems. The sequence is approximately the sequence
in which a new user finds them.

For a catalog of the diagnostics of the compiler, the runtime, a revision, an
assertion, and a fixture, refer to the [Diagnostics guide](diagnostics.md). You
can search that catalog.

## The system does not find `whip`

Cargo installs the binary into `~/.cargo/bin`. Add that directory to the `PATH`.
Then open a new shell:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
whip --version
```

If the `cargo` command itself is absent, install Rust from <https://rustup.rs/>.

## The `start` command supplied no fact

This behavior is correct. The `start` command only makes the instance and
records the event of the start. The `run` command is the full loop on your
machine. The `run` command steps the instance. Add the `--until idle` flag or
the `--wait` flag to continue through the effects. To advance an instance that
you started, use these commands:

```sh
whip --store <store> step <instance_id> --program <workflow.whip>
whip --store <store> worker <instance_id> --program <workflow.whip> --provider fixture
```

## I lost the identifier of the instance, or I used the incorrect store

An instance is in the store file that made the instance. List the content of a
store:

```sh
whip --store .whipplescript/quickstart.sqlite instances
```

Each command that reads an instance needs that same `--store` value. As an
alternative, set the value one time with
`export WHIPPLESCRIPT_STORE=<path>`.

## An example with a counter, a lease, or a queue behaves differently on a second run

A counter, a lease, a ledger, and the builtin queue tracker are in a
coordination store with the scope of the **workspace**. The path is
`.whipplescript/coordination.sqlite`, or the value of
`WHIPPLESCRIPT_COORDINATION_STORE`. That store is *separate* from the run store
of each instance. The `--store` flag and the `WHIPPLESCRIPT_STORE` variable do
**not** reset that store.

This behavior is by design. A `counter failure_budget { cap 3 reset daily }`
declaration is a budget. Each instance shares that budget for that key until the
period changes.

Thus four runs of `examples/circuit-breaker.whip` in one day consume the budget
across the runs. The first three failures go to the `ok` branch. The fourth
failure goes to the `over` branch. The `whip counters` command then shows
`consumed=3`. This behavior is the correct behavior of a breaker. This behavior
is not a bug in one run.

To run such an example with a clean budget, point the coordination store at a
temporary path also:

```sh
WHIPPLESCRIPT_COORDINATION_STORE=$(mktemp -u) \
WHIPPLESCRIPT_STORE=$(mktemp -u) whip run examples/circuit-breaker.whip --until idle
```

Examine or confirm the shared state with the `whip counters` command, the
`whip leases` command, and the `whip ledger` command.

## An agent turn stays in the queue or gets the `blocked_by_profile` status

An agent has a `profile` value. Sometimes the operator plane did not register
that profile. Such an agent compiles clean but cannot run. The first worker pass
marks its `tell` effects as `blocked_by_profile` and gives the reason. An
example reason is `` profile `default` is not registered ``. The line that
reports the idle state of the `run --wait` command lists these effects.

The built-in profiles are `no-repo`, which is the default, `repo-reader`,
`repo-writer`, `internet-research`, `release-operator`, and `permissive`. A package or the operator must register each other profile. A
registration of the profile later removes the block automatically. You do not
put the effect in the queue again.

## More than one workflow needs the `--root` flag

When a bundle of source declares more than one workflow, give the name of the
root:

```sh
whip check examples/revision-ticket-v1.whip --root RevisionTicket
```

The same rule applies to the `run` command, the `step` command, and the
`revise` command.

## The `whip check` command reports an error about liveness

Two faults produce a liveness error, and the code in the head line says which.

1.  **The workflow cannot end.** No rule in it reaches `complete` or `fail`.

    <!-- render: examples/diagnostics/no-terminal-rule.whip code graph.unreachable_terminal -->
    ```text
    error[graph.unreachable_terminal]: workflow `AlertWatch` has no rule that reaches `complete` or `fail`
      --> examples/diagnostics/no-terminal-rule.whip:1:1
      |
    1 | workflow AlertWatch
      | ^
      = help: add a rule that runs `complete <output> { ... }` or `fail <failure> { ... }`, or tag the workflow `@service` if it intentionally runs forever
    ```

2.  **A rule cannot fire.** Nothing in the bundle produces the fact it matches.

    <!-- render: examples/invalid/rule-never-fires.whip code graph.rule_never_fires -->
    ```text
    error[graph.rule_never_fires]: rule `escalate` can never fire: nothing produces `Escalation`
       --> examples/invalid/rule-never-fires.whip:36:8
       |
    36 |   when Escalation as escalation
       |        ^^^^^^^^^^^^^^^^^^^^^^^^
       = help: seed `Escalation` from a table, record it in another rule, declare it as a workflow input, or tag the rule `@external` if it arrives from an external system
    ```

Both help lines carry the repair. The `@service` and `@external` tags they
mention are declarations about the world rather than ways to silence the check;
the [Diagnostics guide](diagnostics.md) says what each one commits you to.

## The `whip doctor` command reports absent tools

The largest part of the tools are optional. Development with the fixture needs
no tool for the formal models, no tool for a decision of a model, and no tool
for a native provider. Install an optional tool only for a formal check or for
work with a true provider.

## The `cargo install --git` command fails

Install from a checkout instead. If that method operates, the failure of the Git
path is a problem with the network, with the lockfile, or with the toolchain:

```sh
git clone https://github.com/GaugeWright/whipplescript.git
cd whipplescript
cargo install --path crates/whipplescript-cli --locked
```

## The checks against a true provider are skipped or fail

You must select the smoke tests against a true provider. Environment variables
control the tests:

```sh
WHIPPLESCRIPT_E2E_REAL_PROVIDERS=1 \
WHIPPLESCRIPT_REAL_PROVIDERS=coerce,codex \
scripts/check-real-providers.sh
```

Read the JSON report of each provider first. The path is
`target/real-provider-reports/<provider>.json`. The report records the position
of the environment, the counts of the checks, and the results of the preflight
checks, which the system redacts. A failure of a provider appears as a
diagnostic, as evidence, and as the status of a run and an effect. Such a
failure does not appear as a generic failure of a command.

## A native agent turn failed and the reason is not clear

The `whip status` command only shows that the instance stopped or failed. The
system records the reason of the provider for a turn that failed. The system
records the reason as metadata of the control plane on the effect. The reason
crosses the boundary of the redaction of the evidence exactly because the reason
is operational and is not the output of a model. Read the reason directly:

```sh
whip diagnostics <instance>   # failure diagnostic carries the provider reason
whip effects <instance>       # effect evidence summary carries it too
```

These are the usual reasons. The value `usageLimitExceeded` means that the run
reached the quota of the Codex plan or the ChatGPT plan. Wait for the window of
the reset. A rejection of the authentication means that you must run the login
procedure of the provider again, such as the `codex login` command. The message
"no model configured" means that you must set the `default_model` value in the
configuration of the provider, or the `model` value in `~/.codex/config.toml`.

The system limits the length of the reason and redacts each secret. Thus the
reason names the cause and does not echo a token. The system keeps the shape
redaction on a prompt and on the output of a model. Those items never appear
here.

## Native provider strict mode fails

The strict mode validates the true native adapters:

```sh
WHIPPLESCRIPT_E2E_REAL_PROVIDERS=1 \
WHIPPLESCRIPT_REAL_PROVIDER_NATIVE_STRICT=1 \
WHIPPLESCRIPT_PROVIDER_CONFIGS=examples/provider-configs/native/native.example.json \
scripts/check-real-providers-report.sh
```

These are the usual messages:

- `WHIPPLESCRIPT_PROVIDER_CONFIGS is required in native strict mode` — set the
  variable to a list of the configuration files of the providers, with a colon
  between the files.
- `command-wrapper provider is not accepted in native strict mode` — the strict
  mode needs the native surfaces of Codex and Claude.
- `missing required native provider config` — add the bindings for `codex-main`
  and for `claude-main`.

For a probe of one provider, use the surface mode instead:

```sh
WHIPPLESCRIPT_E2E_REAL_PROVIDERS=1 \
WHIPPLESCRIPT_REAL_PROVIDER_NATIVE_SURFACE=1 \
WHIPPLESCRIPT_REAL_PROVIDERS=codex \
scripts/check-real-providers-report.sh
```

## The system refuses the destructive tests of a provider

This behavior is by design. These tests need an explicit marker for a target
that you can delete. The tests also need an acknowledgement:

```sh
WHIPPLESCRIPT_REAL_PROVIDER_DESTRUCTIVE_TESTS=1 \
WHIPPLESCRIPT_REAL_PROVIDER_DISPOSABLE_TARGET=native-provider-ci-sandbox \
WHIPPLESCRIPT_REAL_PROVIDER_DISPOSABLE_ACK=I_UNDERSTAND_THIS_PROVIDER_TARGET_IS_DISPOSABLE \
scripts/check-real-providers-report.sh
```

Variants for each provider also exist. The examples are
`WHIPPLESCRIPT_CODEX_DESTRUCTIVE_TESTS` and
`WHIPPLESCRIPT_CLAUDE_DESTRUCTIVE_TESTS`. A report records only that you set the
markers. A report never records the values of the markers.

## A problem with a cloud deploy, a checkpoint, a restore operation, or the executor

The sections above cover a run on your machine and a native run. The runtime on
the edge runs a workflow with no change in a Cloudflare Durable Object. The
[Runtime & operations](runtime-operations.md) guide gives the full surface for
an operator. These are some usual problems:

- The `whip deploy` command targets a Worker and a Durable Object. To make the
  plan and to send nothing, use the `--dry-run` flag. To use the last build
  again, use the `--skip-build` flag. To send the credentials of the providers
  as secrets of the DO, use the `--set-secrets` flag. The full command is
  `whip deploy [--worker-dir <path>] [--config <file>] [--name <worker>] [--dry-run] [--skip-build] [--set-secrets]`.
- The Class-A compute sidecar of the `whip executor` command is not on by
  default. To enable the compute plane in production, do a follow-on step of the
  configuration. A bearer token in the `WHIP_EXECUTOR_TOKEN` variable is
  necessary to bind an address that is not the loopback interface. The sidecar
  also uses the token to authenticate a call in the cluster. Set the token
  before you expose the sidecar. The sidecar binds `127.0.0.1:8080` by default.
  Override the address with the `--bind <addr:port>` flag.
- The `whip checkpoint <instance>` command captures a cut. The
  `whip restore <instance> <cut-id>` command rewinds the state of the files, the
  transcript of the agent, and the position in the event log together, as one
  cut. The command checks the coherence of the cut. The `restore` command does a
  full reconcile operation and makes an automatic checkpoint of the head first.
  These commands use native file I/O only.
