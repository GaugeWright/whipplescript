# CLI reference

This page gives the CLI commands that are implemented, their exit behavior, and
a compact index of the source constructs. The
[JSON reference](json-reference.md) gives the JSON contracts of the runtime. The
[Rust API reference](rust-api.md) gives the internal APIs of the Rust crates.
The [language reference](language-reference.md), the [manual](manual.md), and
[runtime & operations](runtime-operations.md) give the semantics and the
examples.

## Global CLI options

Each CLI command uses the same global shape:

```sh
whip [--store path] [--json] [--input JSON] <command> [args]
```

| Option | Meaning |
| --- | --- |
| `--store path` | The path of the SQLite store. The default is `.whipplescript/store.sqlite`, or the value of `WHIPPLESCRIPT_STORE` when you set that variable. Use `:memory:` for a test in memory. |
| `--json` | Emits machine-readable JSON where the command supports JSON. |
| `--input JSON` | The start input for the `start` command and the `run` command. The declared names of the workflow inputs must key the payload. |

This is the current set of commands:

```text
package, check, compile, verify-report, gov, infoflow, agents, providers,
skills, skill, mcp, lint, lsp, fmt, test, run, start, revise, step, worker, accept,
instances, status, log, facts, effects, runs, artifacts, signal,
ingress, message, mailbox, issue, leases, ledger, counters, evidence,
diagnostics, trace, progressions, progression, otel-export, telemetry, pause,
resume, cancel, checkpoint, restore, handles, fork, retry, recover, auth,
coercion, memory, script, improve, campaigns, campaign, adopt, answer, pin,
suppose, settle, gauges, deploy, executor, doctor
```

The `branch` command and the `stream` command also dispatch. These commands
support the versioned workspace, which is the whip-native VCS. The sections
below give the two commands as experimental. The `whip --help` banner at the
top level groups each command. The dispatch above is authoritative.

To print the usage line of a command, run `whip <command> --help` or
`whip help <command>`.

### Environment variables

| Variable | Meaning |
| --- | --- |
| `WHIPPLESCRIPT_STORE` | The default path of the store when you omit `--store`. |
| `WHIPPLESCRIPT_ITEMS_STORE` | The path of the store of the builtin issue tracker. The default is `.whipplescript/items.sqlite`. |
| `WHIPPLESCRIPT_COORDINATION_STORE` | The path of the state of a lease, a ledger, and a counter. The scope is the workspace. The default is `.whipplescript/coordination.sqlite`. |
| `WHIPPLESCRIPT_EXEC_ALLOW` | The allow-list for a raw `exec "<command>"` statement in the dev profile. The value is a list of glob prefixes with a colon between them, such as `scripts/*:bin/ci-*`. If the value is unset or empty, a raw exec statement blocks at admission with the code `security.script_disabled`. If the list is not empty, a command outside the list fails and does not run. The program must also have a `use std.script` statement. |
| `WHIPPLESCRIPT_EXEC_PROFILE` | The value is `dev`, which is the default, or `hosted`. The hosted profile rejects a raw exec string and needs script capabilities. |
| `WHIPPLESCRIPT_SCRIPT_MANIFEST` | The path of the JSON manifest for the hosted script capabilities. The variable is equivalent to `--script-manifest`. |
| `WHIPPLESCRIPT_RUN_ID` | The identity of the run. The system stamps this identity onto an item that an agent files with the `whip issue new` command. |
| `WHIPPLESCRIPT_PROVIDER_CONFIGS` | The paths of the configuration files for the provider bindings of the worker. A colon separates the paths. |
| `WHIPPLESCRIPT_WORKER_DIR` | The default worker directory for the `whip deploy` command when you omit `--worker-dir`. |
| `WHIP_EXECUTOR_TOKEN` | The bearer token that the `whip executor` sidecar needs for a call that is not on the loopback interface. The comparison uses a constant time. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | The OTLP/HTTP endpoint for the `otel-export` command. The default is `http://localhost:4318`. |
| `OTEL_SERVICE_NAME` | The name of the service that the command attaches to the exported OpenTelemetry resource spans. |
| `WHIPPLESCRIPT_MEMORY_STORE` | The path of the memory store of the workspace. The store supports the `whip memory` command and the `learn`, `recall`, and `curate` verbs. |
| `WHIPPLESCRIPT_IFC_ENVELOPE` | The governance envelope for a governed `whip check` command. The value is a policy file or a signed JSON file. |
| `WHIPPLESCRIPT_GOV_ADMIN` / `WHIPPLESCRIPT_GOV_SIGNER` | The privilege to sign, and the identity of the signer, for the `whip gov sign` command. |
| `WHIPPLESCRIPT_GOV_ESCALATIONS` | The path of the queue for escalations. The `escalate` command of the `whip infoflow` REPL files into this queue. |
| `WHIPPLESCRIPT_PRINCIPAL` / `WHIPPLESCRIPT_USER` | The identity of the principal and the user that acts. The system resolves this identity for the scope of the identity of each user (DR-0031). |
| `WHIPPLESCRIPT_WORKER_CONCURRENCY` | The limit of the thread pool of the worker for each pass. The default follows the quantity of CPUs. Use `1` for serial operation. |
| `WHIPPLESCRIPT_BRAVE_API_KEY` | The Brave key for the web-search tool of the owned harness. |
| `WHIPPLESCRIPT_WEB_ALLOW` / `WHIPPLESCRIPT_WEB_BLOCK` | The lists of hosts that the egress policy of the web tools permits and blocks. |
| `WHIPPLESCRIPT_WEB_SEARCH_FLOOR_MODEL` | The gate for the minimum tier of model for the web-search tool. |
| `WHIPPLESCRIPT_HTTP_SOURCE_ALLOW` | The allowlist of hosts for an `http` ingress source. This is the SSRF policy. |
| `WHIPPLESCRIPT_HARNESS_MAX_TOKENS` / `WHIPPLESCRIPT_HARNESS_TIMEOUT_SECS` | The budget of tokens for each turn, and the limit on the wall clock, for the owned harness. These variables are part of the recorded `WHIPPLESCRIPT_HARNESS_*` family. |
| `WHIPPLESCRIPT_NATIVE_PROVIDER_CONFIGS` | The paths of the provider configuration files for a native adapter. This is the strict-mode variant of `WHIPPLESCRIPT_PROVIDER_CONFIGS`. |
| `WHIPPLESCRIPT_NATIVE_PROVIDER_INACTIVITY_TIMEOUT` / `WHIPPLESCRIPT_NATIVE_PROVIDER_MAX_EVENTS` | The watchdogs for a turn of a native adapter: the limit on inactivity, and the limit on the stream of events. |
| `WHIPPLESCRIPT_CODEX_APP_SERVER_COMMAND` / `WHIPPLESCRIPT_CLAUDE_AGENT_SDK_COMMAND`, `_MODEL`, `_SIDECAR` | These variables override the launch command, the model, and the path of the sidecar of the native adapters. |
| `WHIPPLESCRIPT_TELEMETRY_ALLOWLIST` | The allowlist of attributes for the `otel-export` command. The `--telemetry-allowlist` flag is the equivalent. |
| `WHIPPLESCRIPT_OTEL_ALLOW_INSECURE_HEADERS` | This variable permits OTLP headers over an insecure transport. The default is off. |
| `WHIPPLESCRIPT_IMPROVE_PROPOSER` / `WHIPPLESCRIPT_IMPROVE_PROPOSALS` / `WHIPPLESCRIPT_IMPROVE_PROPOSAL_USAGE` | The selection of the proposer for the improve loop, and the proposals and usage that you inject. These variables apply to a test and to a native run. |
| `WHIPPLESCRIPT_EVAL_CONCURRENCY` | The limit on the parallel evaluation of the candidates of a campaign. |
| `WHIPPLESCRIPT_NO_CONTEXT_FILES` / `WHIPPLESCRIPT_GLOBAL_CONTEXT_DIR` | These variables disable the discovery of the context files of a project for a turn, or move the directory of those files. |
| `WHIPPLESCRIPT_DESKTOP_NOTIFIER` | This variable overrides the notifier command of the `desktop` channel provider. |
| `WHIPPLESCRIPT_BRANCH_STORE`, `WHIPPLESCRIPT_WORKSTREAM_STORE`, `WHIPPLESCRIPT_VCS_CONTENT_STORE` / `WHIPPLESCRIPT_CONTENT_STORE`, `WHIPPLESCRIPT_MAX_BLOB_BYTES`, `WHIPPLESCRIPT_TEXT_MERGE_GAP` / `WHIPPLESCRIPT_TEXT_MERGE_MAX_BYTES` | The stores of the versioned workspace, and the settings for a merge. These variables are experimental and apply to the `branch` command and the `stream` command. |

## CLI commands

### `doctor`

```sh
whip doctor
whip --json doctor
whip --json doctor --providers
whip --json doctor --provider-config examples/provider-configs/native/native.example.json
```

The command opens the configured store or makes the store. The command reports
the version of the schema. The command then checks the optional tools:

```text
maude
python3 or python
python3 -c 'import jsonschema'
java
apalache-mc or apalache
coerce-cli or coerce
codex
claude
```

The helper scripts for the formal models and for the reports use the Python
`jsonschema` package. From a checkout, run `nix develop` or install
`requirements-dev.txt` first. Do this before you run a generated model search or
a validation of a report schema outside the CI environment of the package.

With the `--provider-config` flag, the JSON output has a
`provider_config_checks` field. Each check has the path of the configuration and
the `results` field, and the command redacts the validation results.

With the `--providers` flag, the JSON output has a `provider_health_checks`
field. This field gives a deterministic position for Codex and Claude, and the
command makes no live call. The field reports the availability of the CLI, the
position of the references to the credentials, and the deeper checks that need
an explicit validation against a true provider. The command prints no value of a
credential.

### `package`

```sh
whip package catalog
whip package check <manifest.json>...
whip package lock [--output <path>] <manifest.json>...
```

The command emits the current catalog of the constructs of the platform,
validates the manifests of the packages, and makes lockfiles with the schema
`whipplescript.package_lock.v0`.

A first-class package manifest uses `whipplescript.package_manifest.v0`. The
manifest has separate `libraries`, `capabilities`, `providers`, `profiles`, and
`bindings` sections. The validation of a package derives and validates the
normalized registry of the contracts of the libraries and the effects.

The validation also checks the references at the level of the package. A
current package can expose only a `capability.call` effect contract. The package
must declare each capability that it needs. A binding must name a kind of
provider that the system registers for the bound capability.

The validation accepts a declaration form that is metadata only. Such a form
must use a keyword that is not reserved, an accepted scope, accepted kinds of
field, and `lowering_target: "metadata_only"`. The registry of the contracts
reports such a form for the tools.

The accepted executable target of a declaration is
`lowering_target: "capability_call"`. This target applies to a form in the body
of a rule that names a declared `target_capability` with a matching
`capability.call` effect contract. The first executable form is the memory form
`recall from <pool> for <query> as <binding>`. This form needs a package lock
that authorizes the `recall` verb to lower to the memory recall capability.

The `package catalog` command gives a machine-readable view with no manifest.
The view gives the accepted families of construct, the classes of lowering, the
scopes, the kinds of field, the kinds of interface, the phases, the
cardinalities, and the reserved keywords.

The `package lock` command pins each manifest by its exact SHA-256 value. The
`check`, `compile`, `run`, and `worker` commands can load the lock with the
`--package-lock <path>` flag. When you omit the flag, each command finds a
`whip.lock` file. An explicit `--package-lock` flag wins. If not, the command
searches upward from the directory of the workflow file. If not, the command
searches upward from the current directory. Thus a project with a `whip.lock`
file at its root needs no explicit path, also when you run the command from a
different directory.

If more than one source file on one command line resolves to a different lock,
the command fails and asks for the `--package-lock` flag. If you give no lock
and the command finds no lock, each import of a package that is not in `std.`
fails. An example is `use notes`. Each use of a construct of a package from a
third party also fails. The diagnostic names the items that block the command
and suggests the `whip package sync` command. A program that uses `std.` only is
not affected.

An entry in a lock file can never claim the reserved `std.*` namespace. The
platform contains the embedded std packages. Thus a load of such a lock is an
error.

The system pins each locked manifest by a SHA-256 value. The system computes the
value again over the bytes of the manifest at the time of the load. Thus an edit
to a manifest after the lock operation fails the load of the lock. The kind of
the error is the stable value `package_lock`, and the value appears in the
`--json` output. Run the `package lock` command or the `package sync` command
again to pin the manifest again.

The commands at run time also apply the output contracts of a locked package. A
capability effect of a package with `validation: runtime_boundary` must return a
value that matches its `output_schema`. If not, the run fails before the system
derives a success fact for the package.

### `check`

```sh
whip check [--model-search] [--root Workflow] \
  [--exec-profile dev|hosted] [--script-manifest <path>] \
  [--package-lock <path>] \
  <workflow.whip>...
whip --json check [--model-search] [--root Workflow] \
  [--exec-profile dev|hosted] [--script-manifest <path>] \
  [--package-lock <path>] \
  <workflow.whip>...
```

The command parses the source, resolves the include statements, type-checks the
source, lowers the source to the IR, applies the
[liveness checks](language-reference.md#liveness-checks), and prints the
snapshot of the IR. With the `--model-search` flag, the command also runs the
generated Maude checks when they are available. The generated bridge checks for
the artifacts need Maude, Python, and the Python `jsonschema` package.

With the `--exec-profile hosted` flag, a raw `exec "..."` statement is a check
error. A named `exec <capability> with <record>` form must resolve in the script
manifest that you supply.

With the `--package-lock` flag, an imported library of a package such as
`use notes` resolves against the pinned manifest of the package. The library
then appears in the `contract_registry` field.

The JSON output is an array with one report for each input path. An entry that
succeeds has the hashes of the source, the snapshot of the IR, and the
`source_metadata` field:

```json
[
  {
    "schema": "whipplescript.check_report.v0",
    "path": "examples/provider-language-e2e.whip",
    "status": "ok",
    "workflow": "ProviderLanguageE2E",
    "source_hash": "...",
    "ir_hash": "...",
    "snapshot": "...",
    "source_metadata": {
      "tags": [
        {"name": "fixture", "target_kind": "workflow", "target": "ProviderLanguageE2E"}
      ],
      "descriptions": [
        {
          "value": "Static provider x language task rows",
          "target_kind": "table",
          "target": "language_tasks"
        }
      ],
      "targets": {
        "workflow:ProviderLanguageE2E": {
          "target_kind": "workflow",
          "target": "ProviderLanguageE2E",
          "tags": ["fixture", "acceptance"],
          "description": "Fixture-backed provider x language acceptance workflow"
        }
      }
    }
  }
]
```

An entry with a diagnostic uses `"status": "error"` and has structured spans of
the source.

This is the exit behavior:

| Exit | Meaning |
| --- | --- |
| `0` | Each input compiles, and each optional model search passes. |
| `1` | A diagnostic occurred, or a generated check failed. |
| `2` | The command line has a usage error. |

### `fmt`

```sh
whip fmt <workflow.whip>...           # format in place
whip fmt --check <workflow.whip>...   # report unformatted files, exit non-zero
```

The command formats WhippleScript source into the canonical layout. The format
operation is idempotent. A `fmt` command on source that is already formatted
makes no change.

These are the limits of v0. The two limits are strictly non-destructive. The
`fmt` command reports an error and does not change the file. The command never
damages a file.

- **The command keeps each comment** across each declaration. The command keeps
  a comment on its own line above a top-level declaration or at the head of a
  file. The command keeps a trailing comment on a declaration of one line, such
  as `workflow Demo  # ...`. The command keeps a comment in the body of a
  `rule`, an `apply`, a `coerce`, or a `table`. In the body of a `class`, an
  `agent`, an `enum`, a `signal`, a `tracker`, or a `file store`, the command
  keeps a comment on its own line and a trailing comment on the line of a field
  or a clause. The command interleaves an own-line comment by its position in
  the source. A body of an `enum` variant that carries data has a nested block
  of fields, and the same behavior applies there.

  The command cannot place a comment with no position to attach to. An example
  is a comment that trails the line with the opening brace of a declaration,
  such as `class Task {  # ...`, when that line has no field. In this condition,
  the command **refuses the file and does not remove the comment**. A check for
  no loss makes sure that the command never removes a comment silently.
- The bodies format idempotently. The bodies are a `rule` body, an `apply` body,
  and a `coerce` body, and these include a `"""..."""` string with more than one
  line and a nested `record` block or `complete` block. The command keeps the
  content of a string. The rows of a `table` also format idempotently.

  As a safety net, the `fmt` command also **checks its own idempotency**. The
  command refuses each file that it cannot format stably. Thus the command never
  writes output that drifts or that damages the file. Thus the command never
  damages a construct that the format operation does not cover.

The `--check` flag exits with a code that is not zero if an input is not
formatted or if the command refuses the input. The flag writes nothing.

### `lint`

```bash
whip lint <source-or-dir>... [--root <workflow>]
whip --json lint <source-or-dir>...              # structured findings
whip lint --rule <id> <source-or-dir>...         # run only the named rule(s)
whip lint --deny <id> --allow <id> <source-or-dir>...   # configure actions
```

A positional argument is a file or a directory. The command finds the `.whip`
files in a directory recursively. This behavior is the same as the behavior of
the `whip test` command. The `--rule <id>` flag limits the run to the named
rules, and you can repeat the flag. If you give no rule, each rule runs. With
one source, the JSON report is `{schema, path, findings}`. With more than one
source, the JSON report is `{schema, reports: [{path, findings}, …]}`.

The command gives warnings from a static analysis of a program that already
compiles. For an error, the lint command is a superset of the `check` command. A
program that does not compile reports the compile errors, and the exit code is
not zero. Beyond the errors, the command gives findings about quality.

The analyses of unused declarations flag a construct that only the program can
use and that no part of the program references. Such a construct is
unambiguously dead. Thus these analyses give no false positive:

- **`lint.unused_coerce`** — a `coerce` function that a declaration declares and
  that no statement calls.
- **`lint.unused_lease`** — a `lease` that a declaration declares and that no
  statement acquires.
- **`lint.unused_ledger`** — a `ledger` that a declaration declares and that no
  statement appends to.
- **`lint.unused_counter`** — a `counter` that a declaration declares and that
  no statement consumes.
- **`lint.unused_tracker`** — a `tracker` that a declaration declares and that
  no statement files into or claims.
- **`lint.unused_file_store`** — a `file store` that a declaration declares and
  that no statement reads or writes.
- **`lint.unused_class`** — a `class` that a declaration declares and that no
  part of the program references.
- **`lint.unused_enum`** — an `enum` that a declaration declares and that no
  part of the program references.

These are the other analyses:

- **`lint.noop_rule`** — a rule with an empty body. The rule fires but supplies
  no record, no effect, no `done` statement, and no terminal. The body is
  forgotten or half written.
- **`lint.coerce_result_unused`** — a `coerce <fn>(…) as <binding>` call, where
  no part of the program uses the result `<binding>`. The coercion runs, but the
  program discards its result. The work is dead, or an `after <binding>` handler
  is absent.
- **`lint.broad_file_grant`** — a grant of a `file store`, where the `read` glob
  or the `write` glob matches each item under the root. The globs are `**` and
  `**/*`. The grant is larger than each concrete call needs.
- **`lint.deep_after_nesting`** (`info`) — a rule that nests `after` blocks 4
  levels deep or more. A long chain of effects reads more clearly as a `then`
  chain.
- **`lint.mark_off_consumption_boundary`** — a `mark` whose frozen prefix
  carries a settled effect from a rule that never consumes its trigger. A replay
  of a changed candidate derives the effect again, which is a refire. Thus the
  replay of the prefix refuses the pre-flight check, and the pin degrades to a
  replay of the input. Consume the trigger, or move the mark.
- **`lint.readmission_unprotected_effect`** — a rule that runs work visible
  outside the instance (an agent turn, a coercion, an `exec` command, a
  capability call, a workflow invocation, or a write or an export of a file) on a
  trigger that the program re-presents, while the rule holds no lease and no
  claim. A firing owns its trigger bindings as values, and each effect key
  derives from the identity of the trigger. Thus a re-presentation either repeats
  the work, when the key of the trigger changed, or skips it and rides the
  results of the draining firing, when the key held. The key shape of the
  projection decides which, and the rule does not show it. Acquire a lease keyed
  on the trigger. The analysis reports the two shapes where a re-presentation is
  certain: a readiness projection of a tracker, which re-derives whenever its row
  changes, and a rule that consumes a class and records it again. Refer to
  decision record 0043.
- **`lint.tool_grant_requires_owned_harness`** — an agent with a `tools [...]`
  grant (DR-0025) that does not use the owned harness. The owned harness is
  `provider owned` or a harness of the `owned` kind. The grant is dead, because
  the system resolves and offers a sub-workflow tool only in the brokered loop
  of the owned harness.
- **`lint.envelope_field_on_payload`** — a read of a terminal envelope field
  off a `Completed` payload whose shape is not statically known. The statement
  `after x completes as o` binds the envelope, which carries `tag`, `status`,
  `summary`, `effect_id`, and `run_id`. The arm `case o { Completed as v => … }`
  binds the output of the effect itself. When the effect declares no output
  schema, as an agent turn does, `v` is a boundary of the runtime, and `whip
  check` accepts each field name on it. That is correct, because a read of a
  real output field is the purpose of the arm. It stops being correct when the
  name is one of the five, because the runtime lifts none of them into a
  `Completed` payload. The program compiles, runs the effect, and then fails to
  lower the arm, once a billed and non-idempotent turn has committed. The
  finding is advice, not a rejection, because the output of a model can carry a
  key of that name. Read the field off the alias of the envelope.
- **`lint.missing_coercion_import`**, **`lint.missing_coord_import`**,
  **`lint.missing_files_import`**, **`lint.missing_tracker_import`**, and
  **`lint.missing_ingress_import`** — the program uses a construct with no
  import of its package. The program uses `coerce`, `decide`, or `prompt` with
  no `use std.coercion` statement. The program uses a coordination resource
  (`lease`, `ledger`, or `counter`, and their verbs) with no `use std.coord`
  statement. The program uses a file store (`file store` and the `read`,
  `write`, `import`, and `export` verbs) with no `use std.files` statement. The
  program uses the work tracker (`tracker` and the `file`, `claim`, `release`,
  and `finish` verbs) with no `use std.tracker` statement. The program uses
  typed admission of a signal (a `signal` declaration, an external `source`
  block, or an `emit signal … to` statement) with no `use std.ingress`
  statement. These findings are advice only. This is the graduated sequence of
  imports. The program still runs, but the import names the std package that
  owns and configures the effects.

Each finding resolves to the span of the source of the declaration that it
concerns. The text output puts `:line:col` before each finding, and the numbers
start at 1. The `--json` output emits one finding for each entry, with `code`,
`severity`, `default_severity`, `configured_action`, `message`, and a `range`
field. The `range` field has a `start` and an `end`, each with a `line` that
starts at 0 and a `character` value in UTF-16. This form matches LSP. The schema
is `whipplescript.lint.v0`.

**Configured actions.** The *action* of each rule is a separate axis from its
severity. The system resolves the action in this sequence: the `--allow <id>`
flag and the `--deny <id>` flag, then a `whip.lint.json` file of the project,
then the `warn` default. The CLI wins, then the configuration, then the default:

- **`allow`** — the system suppresses the finding and does not emit the finding.
- **`warn`** — the system reports the finding. The run still succeeds. This is
  the default.
- **`deny`** — the system reports the finding. The run exits with a code that is
  not zero.

A `whip.lint.json` file adjacent to the program sets the action for each rule:

```json
{
  "schema": "whipplescript.lint_config.v0",
  "rules": { "lint.unused_class": "deny", "lint.noop_rule": "allow" }
}
```

An invalid configuration is a `lint.internal` error, and the exit code is not
zero. An invalid configuration has an incorrect schema or an incorrect action.

### `lsp`

```sh
whip lsp     # a Language Server over stdio, launched by an editor
```

This command is a minimal
[Language Server](https://microsoft.github.io/language-server-protocol/) over
stdio. The JSON-RPC implementation is manual and needs no additional dependency
at run time. The v0 version supplies these features:

- **Diagnostics on an edit** — on a `textDocument/didOpen` message and on a
  `didChange` message, the server compiles the document again. The sync of the
  text is full. The server then publishes `textDocument/publishDiagnostics`.
  These are the same diagnostics for the parse operation and the validation that
  the `whip check` command supplies. The editor shows the diagnostics as live
  marks. When the document compiles, the server also publishes the lint findings
  as diagnostics with the `whip lint` tag. Each finding keeps its own severity.
  The canonical set of `error`, `warning`, `info`, and `hint` maps one to one to
  the severities of LSP. Each diagnostic points at the declaration that has the
  problem. A `didClose` message clears the diagnostics.
- **Document symbols** — the `textDocument/documentSymbol` request returns the
  top-level declarations. The declarations are the workflow, the classes, the
  agents, the rules, the signals, the coercions, and the coordination resources.
  An editor uses these symbols for an outline view or a breadcrumb view.
- **Go to definition** — the `textDocument/definition` request resolves the
  identifier under the cursor to its top-level declaration. A top-level name is
  unique in a program. Thus a reference goes to its declaration. The references
  are a `when Ticket` clause, a call to a `coerce` function, and the name of a
  `signal`. A local binding resolves to nothing now.
- **Hover** — the `textDocument/hover` request shows the source of the
  declaration of the symbol under the cursor. Thus a hover on a reference shows
  the definition of the target.
- **Completion** — the `textDocument/completion` request offers the keywords of
  the language and the top-level names that the document declares. The editor
  filters by the prefix that you type. A filter that knows the context and the
  scope is future work.
- **Find references** — the `textDocument/references` request lists each
  occurrence of the top-level symbol under the cursor. The request obeys the
  `includeDeclaration` option.
- **Rename** — the `textDocument/rename` request renames a top-level symbol
  across the document. The request edits each occurrence in the code. The
  request does **not** edit the same word in a prompt string or in a comment.
  Thus the request never damages the content.
- **Formatting** — the `textDocument/formatting` request formats the document.
  The request uses the same formatter that keeps comments as the `whip fmt`
  command. The request returns no edit when the document does not parse or when
  the `fmt` command would refuse the document. Thus the request never damages
  the content.
- **Document highlight** — the `textDocument/documentHighlight` request marks
  each occurrence of the symbol under the cursor. This is the highlight that an
  editor shows continuously at the cursor.
- **Workspace symbols** — the `workspace/symbol` request searches the symbols
  across each open document. The query is a substring, and the search ignores
  the case. An empty query returns each symbol. The v0 version indexes the
  documents that the editor opened. An index across the file system depends on
  the shared service for the symbol index below.

Navigation across files and navigation that knows the scope are in the plan.
These features depend on a shared service for the symbol index. The features are
references across more than one document, local bindings, and symbols across the
file system.

### `test`

```sh
whip test <workflow.whip|dir>...               # files and/or directories
whip --json test <workflow.whip|dir>...        # emit whipplescript.test_report.v0
whip test <workflow.whip|dir>... --list        # enumerate selected scenario ids, run none
whip test <workflow.whip|dir>... -i <pattern>  # include only matching scenarios (repeatable)
whip test <workflow.whip|dir>... -x <pattern>  # exclude matching scenarios (repeatable)
whip test <workflow.whip|dir>... --pass-if-no-tests
```

The command runs the scenarios in the given programs. A scenario has the form
`test "…" { workflow … given … stub … run … expect … }`. Each scenario runs on
an isolated store. Refer to `spec/workflow-testing.md`.

Each positional argument is a `.whip` file or a directory. The command finds the
`.whip` files in a directory recursively. The command skips a hidden entry and
the `target/` directory. The command compiles each source and collects the
scenarios into one report. Each scenario runs against its own text of the
program. Each file that the command finds must compile. A source with an
incorrect form gives exit code 2. The command never skips such a source
silently.

**The identifier of a scenario.** The identifier of each scenario is
`<workflow>::<name>`. The workflow comes from the `workflow` clause of the
scenario, or from the root workflow of the program. The identifier appears in
the `id` field of the report, and you use the identifier for the selection.

**Selection.** The `-i` flag (or `--include`) and the `-x` flag (or `--exclude`)
filter the scenarios by that identifier. A pattern that contains `::` matches
the two halves independently. An empty side matches each value. Thus `Sel::`
selects a full workflow, and `::*passes` selects by the name of a test across
the workflows. A pattern with no `::` matches the name of the test alone. The
`*` character is the only wildcard, and the wildcard matches a sequence of
characters of any length. The command joins the include patterns with OR. If you
give no `-i` flag, the command selects each scenario. An exclude pattern
overrides an include pattern. The `--list` flag prints the selected identifiers,
one for each line. With the `--json` flag, the output is a `tests` array. The
`--list` flag runs no scenario.

**Exit codes.** Refer to `spec/workflow-testing.md`. Code `0` means that each
selected scenario passed. Code `1` means that a scenario ran and failed an
expectation. Code `2` means that the setup is invalid. Such a setup has a
compile error, or a scenario that the harness cannot run faithfully. Code `4`
means that the command selected no scenario. The `--pass-if-no-tests` flag
changes code `4` to code `0`.

The driver runs a scenario in rounds. Each round first drains the evaluation of
the rules until the instance is idle. This is the operation of the `whip step`
command. Each round then settles the effects in the queue, including the agent
turns, through the deterministic **fixture** provider.

The `run` clause controls the quantity of the rounds. A `run until idle` clause,
or a `run until workflow completed|failed` clause, drives the scenario to a
fixed point. The driver stops when the workflow gets to a terminal state or
stops to make progress. A `run for N steps` clause runs exactly N rounds. The
driver stops early only when the workflow becomes terminal. Thus a test can
examine an intermediate state.

The `stub <surface> <outcome>` clause selects the outcome of the fixture. The
outcomes are `succeeds` and `fails`. Thus a workflow that tells an agent and
reacts to a `completed turn` fact runs from end to end under a
`stub agent <name> succeeds` clause. The harness rejects the `times_out` outcome
and the `cancels` outcome as unsupported. The path of the fixture agent is a
harness for a shell command. Such a harness can only exit with 0 or with a code
that is not 0. Thus the harness cannot simulate a timeout faithfully. The
harness does not silently report that the turn succeeded.

This is the scope of the v0 driver. The scenario has a `workflow <Name>` header.

The `given` clauses are these clauses. The `given signal` clause supplies a
signal. The `given input` clause supplies an input, and the driver validates the
input against the input contract of the workflow and seeds the declared input
fact. The `given fact <Type> { … }` clause makes a fact that exists before the
run. The `given clock at "<timestamp>"` clause injects a virtual clock for the
evaluation. Thus a `timer until` deadline and a `timeout` deadline fire
deterministically, or stay pending deterministically. There is no true wait. The
`given tracker <name> issue { … }` clause seeds an issue that exists into the
builtin tracker. The issue is isolated for each scenario. The clause uses the
true `tracker.issue.ready` projection. The
`given file <store> at "<path>" "<content>"` clause seeds a deterministic
fixture file into a declared `file store`. The file is isolated for each
scenario in a temporary directory, and the driver redirects the root of the
store to that directory. Thus a `read` operation runs through the true worker
against the fixture.

The `stub` clauses are `stub agent <name> succeeds|fails` and
`stub coerce <fn> returns { … }`. The second clause injects the typed output of
a coercion that a workflow branches on.

The `run` clauses are `run until idle`, `run until workflow completed|failed`,
and `run for N steps`.

The `expect` clauses are these clauses. The
`expect workflow completed|failed` clause reads the terminal. The
`expect rule <name> fired|did not fire|fired N times` clause reads the firings
of a rule. The effect clauses are
`expect effect <kind> requested|completed|failed` and `expect no <kind>`. These
clauses read the log of the settled effects, and the kind of the effect matches,
such as `agent.tell`. The projection clauses for facts are
`expect <fact> exists`, `expect <fact> where <pred>`, and
`expect <fact> count where <pred> is N`. The `<fact>` value is a dotted name of
a fact. Thus the clause can target a runtime fact such as
`agent.turn.completed`, and also a user fact with one identifier. The
`expect diagnostic <code>` clause reads a runtime diagnostic that the driver
recorded during the run, and the code matches. The driver evaluates each
`expect` target.

The command is honest by construction. The driver cannot run some scenarios
faithfully. An unsupported outcome of a stub is one such scenario. A `given
input` clause that violates the input contract is a different such scenario. The
driver reports such a scenario as **invalid** and gives the reason in the
`diagnostics` field of the scenario. The driver never reports a pass. The runner
never skips an assertion silently. You can stub different agents differently in
one scenario. An example is a `stub agent alpha succeeds` clause with a
`stub agent beta fails` clause.

The JSON output is `whipplescript.test_report.v0`. The output has a `status`
field at the top level, with the values `passed`, `failed`, `invalid`, or
`no_tests`. The output has a `summary` field with the counts `selected`,
`passed`, `failed`, `invalid`, and `skipped`. The output has one object for each
scenario. The object has the `id` field, the bound `workflow` field, the `steps`
field with the `given`, `stub`, and `run` clauses, the `expectations` field with
each `expect` clause and a `passed` status or a `failed` status, and the
`diagnostics` field with the detail of a failure and of an error of the harness.

Refer to `examples/tested-agent-turn.whip` for a complete example. The example
has a workflow and three scenarios. The scenarios use `given input`,
`stub … succeeds|fails`, `run until idle`, `run for N steps`, and the expect
clauses for the workflow, the rule, the effect, the projection, and the
diagnostic.

#### `test replay`

```sh
whip test replay <instance-id>
whip --json test replay <instance-id>
```

This command is a tool to debug a regression. The command is outside the syntax
of a scenario. The command replays the event log of a recorded instance into a
temporary copy of the `--store` value. The command then checks that the
reconstructed projection is identical, byte for byte, to the projection that the
live run built. This is the invariant of **replay equality**. Refer to
`spec/workflow-testing.md`.

The canonical projection is the terminal status of the instance, its active
facts, and its active effects. The comparison excludes the volatile fields,
which are the identifiers of the events, the facts, and the effects, the
timestamps, and the revision epochs. The comparison sorts the arrays. Thus the
comparison does not depend on the sequence or on an identifier.

The command never changes the store of the user. The rebuild operation runs on
the temporary copy. Exit code `0` means that the two projections are equal. Exit
code `1` means that the two projections are different, and the JSON report then
has the `recorded` projection and the `replayed` projection. Exit code `2` means
a setup error, which is an unknown instance or a store that the command cannot
read.

This command operates on an instance in a `--store` value. The command does not
operate on an independent file with a trace or an event log with a `--workflow`
flag. A portable format for a trace in a file is a future extension.

### `compile`

```sh
whip compile <workflow.whip> [--root Workflow] [--package-lock <path>]
whip --json compile <workflow.whip> [--model-search] [--root Workflow] [--package-lock <path>]
```

The command prints the snapshot of the compiled IR. The JSON output has these
fields:

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
  }
}
```

With the `--model-search` flag, a JSON compile report also runs the generated
Maude checks. The checks operate on the emitted IR, on the graph of the
constructs, and on the report of the lowered IR. This option needs the `--json`
flag. A `compile` command with no JSON keeps stdout for the snapshot of the IR.

The generated bridge checks for the artifacts need Maude, Python, and the Python
`jsonschema` package. The CLI passes its current catalog of the constructs of
the platform to the bridge scripts with the `--platform-catalog` flag. Thus an
inherited `WHIPPLESCRIPT_PLATFORM_CATALOG_PATH` setting does not affect the
generated checks. If you run a bridge script alone, pass
`--platform-catalog <path>` or bind the same catalog through the
`WHIPPLESCRIPT_PLATFORM_CATALOG_PATH` variable.

### `start`

```sh
whip [--store path] [--input JSON] start <workflow.whip> \
  [--root Workflow] [--package-lock <path>]
```

The command starts a durable instance and then returns. The command compiles the
bundle of the source. The command makes a version of the program if a version is
necessary. The command makes an instance, appends the `external.started` event,
and seeds the declared input facts of the workflow. The command does not run the
ready rules and does not run a provider. Drive the instance with the
`whip worker` command and the `whip step` command. As an alternative, use the
`whip run` command to execute the instance to idle on your machine in one
command. With the `--package-lock` flag, the command registers the locked
manifests of the packages into the store before the instance starts.

This is the JSON output:

```json
{
  "instance_id": "inst_...",
  "program_id": "prg_...",
  "version_id": "ver_...",
  "workflow": "WorkflowName",
  "store": ".whipplescript/store.sqlite"
}
```

### `step`

```sh
whip [--store path] step <instance> --program <workflow.whip> [--root Workflow]
```

The command runs the deterministic evaluation of the rules for one instance. The
command continues until no more commit of a rule is possible. The command can
make facts, consume facts, put effects in the queue, add dependency edges, and
execute the terminal actions of the workflow. The command never executes a
provider.

This is the output for a person:

```text
step <instance> committed_rules=N facts=N consumed=N effects=N
```

The JSON output has these fields:

```json
{
  "instance_id": "inst_...",
  "committed_rules": 1,
  "facts_created": 1,
  "facts_consumed": 0,
  "effects_created": 2,
  "guards": [],
  "branches": []
}
```

### `worker`

```sh
whip [--store path] worker <instance> \
  [--provider fixture] \
  [--provider-config <path>] \
  [--exec-profile dev|hosted] \
  [--script-manifest <path>] \
  [--package-lock <path>] \
  [--program <workflow.whip>] \
  [--root Workflow] \
  [--once] \
  [--fail | --timeout | --cancel] \
  [--max-child-iterations N]
```

The command starts the effects that it can claim now. The command completes the
effects through the selected provider. The default provider is the
deterministic fixture provider. You can repeat the `--provider-config <path>`
flag to bind the identifier of a harness in the source to a concrete
configuration of a provider. The worker also reads the
`WHIPPLESCRIPT_PROVIDER_CONFIGS` variable, which has a colon between the paths.
The `--fail`, `--timeout`, and `--cancel` flags force a terminal outcome of the
fixture, for a test of a failure path.

For the execution of a hosted script, use the
`--exec-profile hosted --script-manifest <path>` flags. As an alternative, set
`WHIPPLESCRIPT_EXEC_PROFILE=hosted` and
`WHIPPLESCRIPT_SCRIPT_MANIFEST=<path>`. The worker registers the
`script.<name>` capabilities for the program of the instance. The worker
verifies the SHA-256 value before it starts the process. The worker then runs
the argv list directly with JSON on stdin.

With the `--package-lock` flag, the worker registers the locked manifests of the
packages before it checks the policy for the effects that it can claim.

These are the supported kinds of effect. These are the canonical dotted strings
that appear in the `whip effects` output and in the JSON output:

```text
agent.tell
schema.coerce
event.emit
signal.emit
workflow.invoke
exec.command
capability.call
lease.acquire
lease.release
lease.renew
ledger.append
counter.consume
tracker.file
tracker.claim
tracker.renew
tracker.release
tracker.finish
file.read
file.write
file.import
file.export
```

The JSON output has these fields:

```json
{
  "instance_id": "inst_...",
  "provider": "fixture",
  "ran_effects": 1,
  "terminal_events": ["evt_..."]
}
```

### `run`

```sh
whip [--store path] [--input JSON] run <workflow.whip> \
  [--root Workflow] \
  [--provider fixture] \
  [--provider-config <path>] \
  [--exec-profile dev|hosted] \
  [--script-manifest <path>] \
  [--package-lock <path>] \
  [--until idle] \
  [--max-iterations N] \
  [--include-tag TAG] \
  [--exclude-tag TAG] \
  [--stream ndjson] \
  [--fail | --timeout | --cancel]
```

The command runs a workflow on your machine. The command starts a new instance
and alternates a `step` operation and a `worker` operation. The command stops
when the instance becomes idle or when it gets to the `--max-iterations` value.
The command then evaluates the assertions of the source.

The text summary reports the final outcome of the instance. The values are
`status completed`, `status failed`, and `status cancelled`. When the instance
is still `running` and idle, the summary gives the reason. The summary lists a
blocked effect in the text with a pointer to the `whip effects` command. For
each other reason, the summary points at the `whip status` command for the
blocked effects and the failures.

You can repeat the `--provider-config <path>` flag. The command passes the flag
to the worker loop that it contains.

You can repeat the `--include-tag <tag>` flag and the `--exclude-tag <tag>`
flag. The flags select the assertions of the source that the command evaluates
and reports. The flags do not skip a rule, an effect, a provider, or the seed
operation of a table. When the two filters match an assertion, the exclusion
wins.

The `--exec-profile hosted --script-manifest <path>` flags apply the checks of
the hosted script capabilities before the instance starts. The flags pass the
same manifest to the worker that the command contains.

The `--package-lock <path>` flag applies the resolution of the packages before
the instance starts. The flag passes the same lock to the worker loop that the
command contains.

The `--stream ndjson` flag emits compact JSON envelopes for the progress, with
one envelope on each line. The schema is `whipplescript.dev_stream.v0`. The
current events are `dev.started`, `dev.events`, `dev.step`, `dev.worker`,
`dev.idle`, `dev.assertions`, and `dev.report`. The `dev.events` event carries
batches of raw runtime events that the system persisted. The shape of the object
is the shape of the `log --json` output. The `dev.assertions` event carries the
compact summary of the assertions of the executable specification. The final
`dev.report` line contains the same `whipplescript.dev_report.v0` object as the
`dev --json` output.

The JSON output has the identifier of the instance, the name of the workflow,
the `source_metadata` field, a step report for each iteration, the worker
reports, the durable diagnostics for the instance of the run, and compact
summaries of `provider_runs`, `provider_artifacts`, and `provider_evidence`. The
output also has a summary of the assertions of the executable specification,
grouped by the tag of the source, the counts of the assertion filters, and the
reports of the assertions.

The `provider_artifacts` field groups the metadata by the kind of the artifact
and by the MIME type. The field has compact links to the items of the artifacts.
The field does not expose the path or the content of an artifact.

The `provider_evidence` field groups the metadata of the evidence by the kind
and by the type of the subject. The field has compact links to the items of the
evidence. The field does not expose the payloads of the metadata of the
evidence.

A report of an assertion has the `target_id` field, the tags of the source, and
any description of the assertion. The report also has an `event_id` link to the
durable event of the assertion. For an assertion that failed or that gave an
error, the report has `diagnostic_ids` links. The report has deterministic
`reads` of the facts and the effects. Thus an acceptance report can group the
checks by the metadata of the source and by the projections that the checks
validate. Each read has a `match_count` field and the identifiers of the
concrete matches of the facts and the effects, where the identifiers are
available. A match of an effect has the `prompt_content_type` field when the
input of the effect kept a prompt with more than one line and an annotation. The
summaries of the reads of the assertions in an acceptance report also have
compact counts of the items of the traces and the evidence for the grouped
matches of the effects.

### `accept`

```sh
whip [--store path] [--json] accept <fixture.json>
```

The command runs a fixture for acceptance. The fixture is for a test only. The
command uses the same local control-plane path as the `run` command. The command
then validates the final report.

A fixture uses the schema `whipplescript.acceptance_fixture.v0`. A report uses
the schema `whipplescript.acceptance_report.v0`. A report has the
`observed.summary` totals, the grouped summaries of the final counts of the
facts and the effects, and compact summaries of the runs of the providers, the
links of the artifacts, the links of the evidence, the actions of the control
plane, the metadata of the source, the reads of the assertions, the diagnostics,
the traces, the inbox, and the executable specification. The report also has the
full `whipplescript.dev_report.v0` object under the `dev_report` field. A
relative entry in the `workflow` field and in the `provider_config_paths` field
resolves from the directory of the fixture file.

A fixture can assert these items: a diagnostic by its code; a summary of the
executable specification; a group of the executable specification with a tag and
without a tag; a deterministic read of an assertion and the metadata of a match,
such as the content type of a prompt and the counts of the links of the traces
and the evidence; the counts of the actions of the fixture; the final totals of
the facts and the effects; the grouped final counts of the facts and the
effects; the targets of the metadata of the source; the counts of the runs of
the providers; the counts of the artifacts that are metadata only; the counts of
the evidence that is metadata only; and the counts of the items in the inbox of
a person.

An observed group of matches of a read of an assertion has compact
`trace_sequences` links and `evidence_ids` links for a detailed examination. The
observed summary of a trace reports the totals of the events, the groups of the
reconstructed abstract trace events, the compact items of the abstract trace,
and the conformance. A fixture can assert the fields of the summary of a trace,
the groups, and the stable selectors of the items, through the `expect.trace`
field. An entry in the `expect.assertion_reads` field must have a minimum of one
selector. The selectors are `source`, `kind`, `head`, and `guard`.

The v0 command accepts one path of a fixture. An external runner for a suite
must isolate the store for each fixture.

A fixture can also supply entries in the `setup.facts` field. Each entry has a
declared class in the `name` field, an optional stable `key` field, and a JSON
`value` field. The command validates each setup fact against the schema of the
class of the workflow. The command then derives the fact into the instance that
it started. The command does this before the setup actions and before the usual
loop of the run.

The command rejects the `setup.effects` field and the `setup.artifacts` field in
v0. The usual rules, the workers, and the providers must supply the effects and
the artifacts.

The `actions` field of a fixture can apply a true `pause`, `resume`, or `cancel`
transition of the control plane before the dev loop.

The command checks the shape of each field of the fixture and of each field of
an expectation before the workflow starts. Thus the command rejects an
expectation with an incorrect type. The command does not treat such an
expectation as absent.

### `revise`

```sh
whip [--store path] revise <instance> <workflow.whip> \
  [--root Workflow] \
  [--dry-run] \
  [--cancel keep|queued|running] \
  [--carry old=new]
```

The command checks that a candidate bundle of source can become the active
version of the program for an instance that runs and that is not terminal. With
the `--dry-run` flag, the command reports the compatibility and does not change
the store. Without the `--dry-run` flag, the command records an event that
activates the revision. Each subsequent `step` command then uses the new active
version of the program.

The policy for the cancel operation controls the effects of the old version:

| Policy | Meaning |
| --- | --- |
| `keep` | Keeps the effects of the old version claimable and able to run. |
| `queued` | Cancels the effects of the old version that are in the queue, blocked, or claimable. The cancel operation is terminal. |
| `running` | Cancels the effects of the old version that are in the queue. The command requests a cancel operation for the work of the old version that runs now. |

A request to cancel work that runs is not a terminal result. A provider still
records the eventual completion, failure, timeout, or acknowledgement of the
cancel operation.

The command reports what the revision does to the rules of the program. The
identity of a rule firing is the name of the rule. Thus a revision that renames
a rule fires that rule a second time for a trigger that the rule already fired
on, and performs its action a second time. The command derives which removed
rule corresponds to which added rule and reports each such correspondence, each
removed rule that corresponds to nothing, and each correspondence that is too
ambiguous to propose. These are diagnostics. The command does not treat them as
incompatibility, and does not block the revision.

The command does not act on a correspondence that it derives. No hash of the
content of a rule distinguishes a rename from the deletion of one rule and the
copy of its body into another. Thus the command suppresses the second firing
only for the carry that the operator states:

| Flag | Meaning |
| --- | --- |
| `--carry old=new` | A firing recorded under the rule `old` counts as a firing under the rule `new`. |

The flag accepts either the bare name of a rule or the identity of the
declaration (`rule old`), and the flag may appear more than once. The rule `new`
must be a rule that the candidate program declares. The rule `old` must not be,
because a rule whose name survives a revision was not renamed. The command
records the carry and the derived correspondence on the activation, and keeps
them apart: the carry is the instruction of the operator and the correspondence
is the evidence of the system.

The JSON output of a dry run has the candidate version, the diagnostics about
the compatibility, the rule correspondence, the carries, the impact on the
agents, the impact of the cancel policy, and no event of activation. The output of an activation has the version that the
command activated, the epoch of the revision, the policy for the cancel
operation, the diagnostics, and the links to the evidence.

### Inspection commands

| Command | Meaning |
| --- | --- |
| `instances` | Lists each instance in the configured store. |
| `status <instance>` | Shows the status of the instance, the counts, the recent events, the pending time effects, and the links to the invocations of the workflows. |
| `log <instance>` | Shows the append-only log of the events. |
| `facts <instance>` | Shows the current facts that no rule consumed. |
| `effects <instance>` | Shows the effects, the status, the target, the profile, and the reason for a block. |
| `runs <instance>` | Shows the attempts of the runs of the providers. |
| `artifacts <run-id>` | Shows the metadata of the manifest of the artifacts for a run of a provider. The command groups the recorded artifacts by kind and by MIME type. Use the command with `evidence instance` to find the effect that supplied an artifact. |
| `evidence instance <instance-id>` | Shows the records of the evidence of an instance and their links. |
| `evidence [<gauge>]` | The view of the evidence of a gauge: the estimates and the flags for a contradiction that continues. The data is the same as the data of `whip gauges`. |
| `progressions <instance>` | The view for each firing: the pinned bindings of the trigger, the effects that the firing requested with their statuses, the state of the firing, the state of the region, and a `trigger no longer live; consumed by <rule> at #<seq>` annotation for a trigger that is no longer live. The field in the `--json` output is `stale_triggers`. |
| `progression cancel <instance> <firing-id> [--reason <text>]` | Closes one open firing precisely. The command cancels the effects of the firing that are in operation and records a `progression.cancelled` event. The command does not touch the instance and does not touch an adjacent firing. |
| `diagnostics <instance>` | Shows the durable diagnostics. |
| `trace <instance> [--check]` | Shows the bundle of the trace. With the `--check` flag, the command reconstructs the abstract trace and runs the conformance checks. |

Each command for inspection supports the `--json` flag. A fact that a `table`
declaration seeded appears in the JSON output with
`"provenance_class": "table"` and a `source_span` field whose `construct` value
is `"table_row"`.

### `signal`

```sh
whip [--store path] [--json] signal <instance> \
  --name <signal.name> \
  --data <json> \
  --program <workflow.whip> \
  [--root Workflow] \
  [--delivery-id <id>]
```

The command validates the payload of an external signal against the declared
`signal <name> { ... }` schema of the bundle of the source. The command appends
the fact of the signal to the log of the instance. The command then derives the
typed fact that a rule matches with a `when <signal.name> as x` clause or with
the general `when fact <signal.name> as x` form. The command rejects a signal
with an incorrect form and a signal with no declaration. The command does this
before a fact with an incorrect type can enter.

The `--delivery-id` flag supplies the identity of the delivery from the provider
or from the operator. This identity wins over the derived hash of the payload as
the key for the admission. Thus a second run with the same identifier admits one
fact, and this behavior continues across the runs of the process. The command
absorbs the duplicate and gives a diagnostic. The `--json` output has
`"duplicate": true` and names the original event. The command does not make a
second fact.

The output for a person prints the sequence of the signal. The JSON output has
these fields:

```json
{
  "instance_id": "inst_...",
  "signal": "deploy.finished",
  "event_id": "evt_...",
  "fact_event_id": "evt_..."
}
```

This is the exit behavior:

| Exit | Meaning |
| --- | --- |
| `0` | The command accepted the signal and derived the typed fact. As an alternative, the command absorbed a duplicate delivery. |
| `1` | The validation of the store, the source, or the payload failed. |
| `2` | The command line has a usage error. |

### `ingress serve`

```sh
whip [--store path] ingress serve --stdio --program <workflow.whip> [--root Workflow]
```

This command is the resident driver for admission over stdio. The identifier is
`std.ingress.stdio`. The command is a reference path for development and for
tests. The command reads JSONL envelopes from stdin. An envelope has the form
`{"instance", "signal", "payload", "delivery_id"?}`. The command admits each
envelope through the same core for admission as the `whip signal` command. The
core checks the declaration of the signal, validates the payload, applies the
gate for the internal channel, and uses an idempotent key for the delivery.

The command writes one line of JSON with the result for each envelope on stdout.
The `"status"` field is `admitted`, `duplicate`, or `rejected` with a `reason`
field. The command rejects a line with an incorrect form before it makes a fact.
The process exits with code `0` at the end of the input. The driver for an HTTP
listener is deferred. Refer to the "Deferred with cause" section of
`spec/std-ingress.md`.

### Issue commands

```sh
whip issue new --tracker <TR> --title <T> [--body <B>] [--label <L>] [--actor <A>]
whip issue list [--tracker <TR>] [--status <S>]
whip issue show <id>
whip issue ready <tracker> [--limit <N>]
whip issue claim <id> [--actor <A>]
whip issue renew <id> [--actor <A>]
whip issue release <id>
whip issue finish <id> [--summary <S>]   # alias: complete
whip issue fail <id> [--actor <A>]
whip issue dep add <blocked> depends-on <blocker>
whip issue rebuild
```

The issue commands operate the builtin issue tracker. Refer to
[trackers](language-reference.md#trackers). The scope of the builtin tracker is
the workspace. The tracker stores the items in `.whipplescript/items.sqlite`.
Override the path with the `WHIPPLESCRIPT_ITEMS_STORE` variable. The tracker
gives sequential identifiers: `WS-1`, `WS-2`, and so on.

The `--status` flag filters on the categories of status. The categories are
`open`, `in_progress`, `closed`, `canceled`, and `archived`.

Each command that changes an item returns the full row of the issue. With the
`--json` flag, the row is JSON. Thus an agent never needs a subsequent `show`
command.

A claim is a local lease at run time, and the system keeps a claim separate from
the durable status. A plain `claim` command puts the `in_progress` overlay on
the issue and projects the issue as not ready. The command does no durable
write. The `release` command, the `renew` command, which is a heartbeat that
only the holder can send, and the automatic release at a terminal manage the
lease.

The `dep add` command records a `blocks` edge. The blocked issue then waits
until the blocker closes.

The identity of the actor defaults to the stamp of the identity of the run. The
stamp comes from the `WHIPPLESCRIPT_RUN_ID` variable or the
`WHIPPLESCRIPT_INSTANCE_ID` variable. Override the identity with the `--actor`
flag. Thus an item that an agent files or claims during a turn carries the
provenance of the identity of the run.

### Coordination inspection

```sh
whip [--json] leases [<resource>]
whip [--json] ledger [<ledger>] [--partition <value>]
whip [--json] counters [<counter>]
```

These commands examine the coordination state with the scope of the workspace. A
`lease` declaration, a `ledger` declaration, and a `counter` declaration make
this state, together with their `acquire`, `release`, `append`, and `consume`
effects.

The commands read `.whipplescript/coordination.sqlite` by default. The commands
read the value of `WHIPPLESCRIPT_COORDINATION_STORE` when you set the variable.
The commands do not use the `--store` value of an instance. A coordination
resource deliberately continues after a run store is deleted.

The [JSON reference](json-reference.md) records the shapes of the JSON output.

### Lifecycle commands

```sh
whip pause <instance>
whip resume <instance>
whip cancel <instance>
whip retry <instance> <effect>
whip recover <instance>
```

| Command | Meaning |
| --- | --- |
| `pause <instance>` | Changes an instance that runs into the paused state. The rules stop to commit, and the workers stop to claim, until you resume the instance. A pending effect keeps its state. |
| `resume <instance>` | Changes a paused instance back into the running state. The next `step` pass and the next `worker` pass continue from the position in the record. |
| `cancel <instance>` | Changes an instance that runs or that is paused into the terminal cancelled state. This is an act of an operator, and it is different from a `fail` statement of the workflow. The command releases the leases and the claims that the instance holds. |
| `retry <instance> <effect-id>` | Moves an effect that failed or that timed out, and that is eligible, back into the queue for another attempt by a provider. The alternative at the level of a rule is the pattern of retries as facts. Refer to chapter 13 of the manual. |
| `recover <instance>` | Reconciles the runs of a native provider that stopped. The command uses the evidence of the provider that the system persisted. |

A terminal instance absorbs each subsequent operation. An instance that
completed, failed, or was cancelled accepts no more public transitions of the
lifecycle and no more commits of a rule.

### `otel-export`

```sh
whip [--store path] otel-export <instance> [--dry-run]
```

The command reads the terminal runs of the providers from the store of the
instance. The command emits OTLP/HTTP JSON spans. The log of the events and the
tables of the runs of the providers are the buffer. A file with a cursor,
adjacent to the SQLite store, records the identifiers of the runs that the
command exported. Thus a second pass of the exporter emits each span one time.
The `--dry-run` flag prints the payload and does not write the cursor.

This is the configuration:

| Variable | Meaning |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | The endpoint of the collector. The default is `http://localhost:4318`. |
| `OTEL_SERVICE_NAME` | The name of the service in the resource. The default is `whipplescript`. |

This is the exit behavior:

| Exit | Meaning |
| --- | --- |
| `0` | The export succeeded, or no new data was present, or a dry run printed the payload. |
| `1` | A read of the store failed, an HTTP export failed, or the command could not write the cursor. |
| `2` | The command line has a usage error. |

### `telemetry`

```sh
whip [--store path] [--json] telemetry status
whip [--store path] [--json] telemetry reset-cursor [<instance>]
```

The command manages the cursor of the `otel-export` command. That cursor makes
the command emit each span one time. The `status` subcommand reports the
endpoint of the exporter, the name of the service, and the count of the runs
that the command already exported for each instance. The `reset-cursor`
subcommand clears the cursor. The subcommand clears the cursor for one
`<instance>` value, or for each instance when you give no argument. The next
`otel-export` command then sends from the start. The two subcommands do not
touch the execution of a workflow.

### `message`

```sh
whip message <instance> --channel <name> --text <text> \
  [--markdown <md>] [--by <sender>] [--thread <id>] \
  --program <workflow.whip> [--root <workflow>]
```

The command injects an inbound message of a channel into an instance that runs.
The command compiles the program. The command checks that `<name>` names a
declared `channel`. The command builds the generic `Message` envelope. The
command then derives a `message.<channel>` fact. A rule matches this fact with a
`when message from <channel> as x` clause.

A message needs the `--text` flag or the `--markdown` flag, or the two flags. A
channel with no declaration is a usage error. An absent instance is also a usage
error.

The `--by` flag records the identity of the sender that the message claims. The
`--from` flag is an alias. The `received_at` value is the instant of the
injection. The system makes the identifier of the message for each delivery.
Thus a second send operation with identical text is a different message. The
JSON output has the identifier of the recorded event and the identifier of the
derived fact.

### `mailbox`

```sh
whip mailbox outbound [--channel <name>] [--limit <n>]
whip mailbox inbound <channel> [--limit <n>]
```

This command is the read surface over the files of the LOCAL messaging provider.
The `outbound` subcommand lists the rows that a `send via` statement on a
`local` channel delivered to `<store>.mailbox.jsonl`. The `--channel` flag
filters the rows. The `inbound <channel>` subcommand lists the rows that the
provider received in `<store>.inbox.<channel>.jsonl`, with their ordinals of
admission. The command is read-only. The injection operation stays with the
`whip message` command. The `--json` flag emits the full records.

## Cloud deployment and runtime

The same durable kernel of rules and effects that runs on your machine also runs
without a change in a Cloudflare Durable Object wasm isolate. The `deploy`
command publishes a workflow to that runtime on the edge. The `executor` command
is the optional Class-A sidecar for computation.

### `deploy`

```sh
whip deploy [--worker-dir <path>] [--config <file>] [--name <worker>] \
  [--dry-run] [--skip-build] [--set-secrets]
```

The command deploys a workflow to a Cloudflare Worker and its Durable Object.
The command does this in one operation. The command needs `npm` and `wrangler`
on the `PATH`. The command stages the bundle of the worker. The command can
build the bundle. The command then publishes the bundle.

The `--worker-dir` flag selects the directory of the worker. As an alternative,
set the `WHIPPLESCRIPT_WORKER_DIR` variable. The `--config` flag selects one
wrangler configuration inside that directory. A directory with one configuration
needs no flag. A directory with several has no default: the command stops and
names them, because one worker source published under several names cannot be
deployed by a guess. The `--dry-run` flag validates the
bundle and publishes nothing. The `--skip-build` flag uses a build that exists.
The `--set-secrets` flag sends the provider credentials that you set on your
machine as secrets of the Worker. The flag skips a key that you did not set on
your machine and gives a note.

On the edge, a timer and a deadline fire through an alarm of the Durable Object.
The provider credentials come from the secrets of the Durable Object.

### `executor`

```sh
whip executor [--bind <addr:port>]
```

The command runs the Class-A sidecar for `exec` operations. The sidecar supports
the true toolchains of the compute plane. The sidecar serves the
`whip-executor/1` protocol. The default bind address is the loopback interface
only, at `127.0.0.1:8080`. An entrypoint of a container binds `0.0.0.0:8080`.

A call in the cluster authenticates with a bearer token. The comparison uses a
constant time. The variable is `WHIP_EXECUTOR_TOKEN`. The sidecar refuses a call
that is not on the loopback interface and that has no token.

The compute plane is built, and a live test proved the compute plane. The plane
has this Class-A sidecar and the Class-B path with a container for each turn. To
enable the plane in production, do a follow-on step of the configuration. The
plane is not on by default.

## Restorable context

The `checkpoint` command and the `restore` command rewind the work of an agent
to an earlier point. The work is the files of the agent, the transcript of the
agent, and the position of the instance in the event log. The two commands
rewind these three planes as one consistent cut, and the system checks the
coherence of the cut. The system captures the history of the files by their
content. Thus a restore operation returns the exact bytes of the earlier
version. The two commands support native file I/O only.

### `checkpoint`

```sh
whip [--json] checkpoint <instance> [--cut-id <id>] [--external-positions <json|@file>]
```

The command captures a checkpoint of the three planes of the instance at the
current position of the events. The `--cut-id` flag names the cut. When you omit
the flag, the command makes an identifier with a timestamp.

The output for a person reports the identifier of the cut, the sequence of the
event, and the count of the files that the command captured. The JSON output
also has the hash of the manifest.

The `--external-positions` flag records the **pair** of positions for a backup
or a handoff across stores. The positions of the scope of an external authority
travel in the same fenced `plane.positions` event as the identifier of the cut
of the workspace. The value is inline JSON, or `@path` for a file. Thus the two
stores restore to one coherent coordinate. Read the pair back with the
`whip handles` command.

### `handles`

```sh
whip [--json] handles <instance>
```

This command is the surface of the handles that you can reference. The schema is
`whipplescript.handles.v0`. The handles are the stable pointers. An external
policy authority admits its decisions against these pointers. Each fact has one
owner. Thus the log of the authority records the decisions and these pointers,
and whip continues to own the facts.

The command reports the most recent position of the instance in the event log,
the identifiers of its effects with their statuses, the line of the binding of
the workspace with the head and the recent identifiers of the cuts, and the most
recent cut with a pair of positions. Refer to
`spec/store-seam-contract-draft.md` for the contract of the seam that these
handles serve.

### `restore`

```sh
whip [--json] restore <instance> <cut-id>
```

The command restores the instance to the named checkpoint. The command first
checks the coherence of the cut. If the check fails, the command refuses the cut
and changes nothing. The command does not apply a part of a cut.

The command then makes an automatic checkpoint of the current head. Thus you can
undo the restore operation. The command then applies the reconcile operation on
the files. The command writes the paths of the manifest back to the content of
the cut. The command removes each file that a person made after the cut. The
command then commits a `context.restored` marker. That marker folds the plane of
the instance and the plane of the transcript to the cut.

The line that reports the success gives the name of the
`auto-before-<cut-id>` checkpoint. Restore to that checkpoint to undo the
operation. The exit code is `1` if the command refuses the cut.

### `fork`

```sh
whip [--json] fork <instance> [--agent <name>] [--branch-id <id>]
```

This command is the fork of a chat. The command makes a **new** instance. The
thread of the agent of the new instance comes from the turns that the source
completed. When a branch binds the source, the file surface of the new instance
is a new branch. The command forks that branch at the head of the line of the
source and binds the branch at the time of the birth of the instance.

The command takes the two planes from one quiet coordinate. An effect that runs
refuses the fork.

The fork inherits the version of the program, the input, and the authority of
the source. The fork does not inherit the history of the events of the source.
Thus the fork never reports that it executed the effects of the source.

The command does not replay the start of the workflow. Drive the fork with the
`whip signal` command or the `whip message` command. The next `thread continue`
turn of the fork continues the conversation from the seed. A file effect of the
fork lands on its own line with effect keys that are different from the keys of
the source.

The `--agent` flag selects the thread when more than one agent completed a turn.
The default is the agent of the most recent turn that completed. The
`--branch-id` flag names the branch of the fork. A source with no branch forks
the thread only, and the command reports this result honestly.

The JSON output has the identifier of the new instance, the count of the
messages in the seed, the coordinate of the source, and the pair of the branches
or the value `null`.

## Improve (experimentation surface)

The evidence of the gauges, the pinned scenarios, and the records of the
campaigns are in an improve store with the scope of the workspace. The path is
`.whipplescript/improve.sqlite`, and the variable is
`WHIPPLESCRIPT_IMPROVE_STORE`. This store is separate from a run store that you
can delete.

### `pin`

```
whip [--json] pin <instance> [at <mark>] --as <name>
```

The command pins a run as a named scenario. Thus the corpus for the regression
tests comes from use and not from authoring.

A bare pin freezes the input of the run. A regeneration then runs the full
workflow again. An `at <mark>` clause freezes the prefix at the first time that
the run got to the declared mark. A regeneration then replays that prefix. A
replayed effect never fires again. The regeneration then executes only the
suffix again. Thus the two arms pair at the cut.

### `suppose`

```
whip [--json] suppose <scenario> [--program <workflow.whip>] [--root <workflow>]
     [--provider <name>] [--provider-config <path>]
```

The command does one regeneration of the pinned scenario. The regeneration uses
the current program or a candidate program. This command is the usual method to
ask a question about an alternative during a debug operation.

A pin at a mark replays the frozen prefix. The command scores the recorded run
in position as the paired control. The output gives
`recorded → regenerated` for each gauge, with the decisions about the bars, the
accounting of the replay, which is the quantity of the events that the command
replayed and the quantity of refires, and the tags for honesty. The tags are
`prefix-replay`, `replay-refire`, `clock-sensitive`, and `replay-fallback`.

The line for each gauge carries the `p_better` value. This value is the Bayesian
sign test over the pair of the recorded value and the regenerated value, under a
Jeffreys prior. The value is present when the two sides carry decisions about a
bar. One continuous delta has no scale. Thus the t family stays silent at N=1.

Each suppose operation lands in the ledger of the evidence. A candidate program
that is not compatible with a revision of the frozen prefix degrades honestly to
a replay of the input.

### `settle`

```
whip [--json] settle <gauge> [--certify] [--threshold <k>] [--spend-cap $<n>]
     [--program <workflow.whip>] [--root <workflow>]
     [--provider <name>] [--provider-config <path>]
```

The command names the decision, which is the declared bar of the gauge. The
command refuses a gauge with no bar. The command then lets the system stop
itself.

The regenerations race in a round-robin sequence over the pinned scenarios. Each
observation that passes the bar increases the level of the evidence. Each
observation that is contrary decreases the level, and the floor is zero. The
race continues until the level crosses the threshold, which gives the result
`bar-cleared`, or until a full pass over the pool adds no evidence, which gives
the honest result `undetermined`. An operator never selects a quantity of
samples.

The crossing is valid at any time, because the shape is a sequential e-process.
Thus a stop at the crossing is correct.

The `--certify` flag records the observation of the crossing with a
`certificate` tag and makes an identifier of a certificate.

The `--spend-cap` flag is a limit in currency. The flag is never a quantity of
samples. The flag stops the race when the **priced** cost of the regenerations
crosses the value. The result is an honest `undetermined` with the reason
`spend-cap-reached`. The `prices` block of the configuration of the provider
gives the rates. Usage with no price cannot bind the cap.

Each regeneration of a settle operation lands in the ledger of the evidence with
the `settle` tag.

With the walk, the `p_bar_met` value reads out the Jeffreys Beta posterior that
a regeneration passes the bar. The command references the value at the rate of
the chance bar itself. This value is a readout. This value is never the rule
that stops the race.

### `gauges`

```
whip [--json] gauges [<gauge>]
```

The command gives the accumulated evidence of the gauges. The output has the
mean, the N value with the division between regenerated observations and live
observations, and the counts of the passes. A row from an ambient observation
lands from the `whip run` command automatically, for a deterministic judge. Such
a judge is an `exec` judge or a builtin judge.

The output also carries **flags for a contradiction that continues**. For each
accepted answer about a trade, live evidence under the hash of the program of
the accepted candidate folds into a posterior of a contradiction against the
operating point at the time of the answer. The command raises a ⚠ line, which is
the `contradictions` field in JSON, only in two conditions together. The
posterior is 0.8 or more, and the posterior did not decrease over the last three
informative observations. Thus the flag is for a sustained condition and never
for a spike. The flag is advice and gives the precedent. To revoke the answer,
use the `whip answer --revoke` command.

### `improve`

```
whip [--json] improve [<gauge>[>=<target>] ... [then ...] | <campaign>]
     [--program <workflow.whip>] [--sacrifice <gauge>] [--within <gauge>=<band>%]
     [--spend-cap $<n>] [--proposer fixture|native] [--provider <name>]
     [--redacted-view]
```

The command runs a campaign for an improvement. The gauges that you name express
the division. A gauge that you name ascends. A gauge that you do not name is
guarded in a band of indifference. The `--sacrifice` flag releases a gauge. A
declared bar is always hard.

The `--spend-cap` flag applies to the **priced** cost that the system recorded.
The rates come from the `prices` block of the configuration of the provider. The
values are in USD for each million tokens, for each provider and model, with the
input side and the output side separate. The rates are in the configuration
only. The system ships no default rate. Usage with no matching rate records
honestly as `unpriced` with a cost of 0, and such usage cannot bind the cap.

A campaign that crosses its cap **parks**. The record then has a
`campaign.parked` event, and the report has `"parked": true`. The
`whip improve --resume <campaign-id>` command continues the campaign under a new
allowance for that invocation. The specification, the program, and the numbers
of the candidates come from the record. If the program changed, the command
refuses the operation because of the guard on the hash of the baseline.

An inline target such as `extract_quality>=0.9` becomes a reach bound. The
`then` keyword separates the lexicographic stages, and the stages have ratchet
semantics. A stage whose reach targets the baseline already meets advances at
the time of the invocation. Its levels then become hard floors for the guards of
the later stages, and the record has a `stage.advanced` campaign event. A stage
with no target is maximization with no limit, and such a stage never advances
automatically.

One positional argument that names a declared `campaign` adopts the
specification of that campaign. A bare `whip improve` command is the repair
mode.

This is the loop. The command seals a holdout set. The set is 20 percent of the
pinned scenarios, with a floor of 2 scenarios. Below 4 scenarios, the campaign
runs with the `unheld-out` tag. The command then evaluates the baseline. The
command then repeats these steps: propose a candidate, apply the static gate,
evaluate the candidate, give a verdict on the dominance, and apply the sealed
gate for a promotion.

The command proposes a candidate only when the candidate improves a gauge in the
ascend set, causes no regression in a guarded gauge, and meets each bar. The
command surfaces a true trade as a decision. The command never accepts a trade
automatically.

The proposer never sees the content of a sealed scenario, and the proposer sees
the aggregates only. The `--redacted-view` flag, or a declared
`proposer redacted` clause, extends this limit to the content of EACH scenario.
The evidence of the campaign then has the `proposer:redacted-view` tag.

The command checks each candidate for fragments of the payload of a scenario
that are new in its source and that are identical to the original. A match puts
the `leakage-overlap` tag on the card. The tag is a flag and never a block. The
adoption stays the act of a person, and the system audits that act.

The terminal state is one card of evidence for each candidate. The command
proposes. The command does not apply.

### `campaigns` / `campaign`

```
whip [--json] campaigns
whip [--json] campaign <id>
```

These commands give the folded records of the campaigns. The records have the
candidates that the campaign considered, the cards of the evidence as they were
at the time, the seal operation, and the decisions about the adoptions. This is
the data for an examination of the history of the program.

### `adopt`

```
whip [--json] adopt <campaign>:<candidate> [--program <workflow.whip>]
```

The command writes the source of a candidate into the program. This is the
explicit act of adoption by a person. The command is for a candidate that the
campaign proposed, or for a trade that a person accepted with the
`whip answer` command. The command refuses honestly when the program changed
after the campaign evaluated its baseline.

### `answer`

```
whip [--json] answer <campaign>:<candidate> --accept|--reject|--revoke [--by <who>]
```

The command answers a trade that the system surfaced. Only a `candidate.tradeoff`
decision is answerable.

The answer is a **precedent**. A precedent is a recorded speech act. A precedent
makes an accepted candidate available for adoption. By default, a precedent also
resolves a future trade automatically, by *monotone dominance of the precedent*.
A new trade that is as good as an accepted precedent on each gauge, or better,
accepts automatically. A new trade that is as good as a rejected precedent on
each gauge, or worse, rejects automatically. Each other trade asks a person.
This includes a trade between the two conditions, a trade that conflicting
precedents cover, and a trade outside the band around the operating point at the
time of the answer.

Each automatic resolution gives its precedent on the card of the evidence. The
tags are `auto-resolved:precedent` and `auto-rejected:precedent`.

The `--revoke` flag withdraws the answer and each authority that the answer
granted.

## Credentials

### `auth`

```sh
whip auth status
whip auth set <openai|anthropic> <key>
```

The command manages the credentials of the native coerce providers. The `status`
subcommand reports, for each provider, the source of a credential and a preview
that the command redacts. With the `--json` flag, the output has the
`whipplescript.auth_status.v0` schema and a `configured` flag. The `set`
subcommand stores a key for `openai` or for `anthropic`. There is no `login`
subcommand. Whip runs no OAuth procedure.

Every credential this resolver finds is one whip holds itself, so `status` also
reports it as **degraded at r0** — `credential_ref`, `rung`, and `degraded` in
the JSON, and a second line in the text output. This layer predates the
custodian of DR-0053, and a report that named only the source read exactly like
one naming a custodian entry at the same rung. The rung a `require credential
<rung>` clause compares against is the one the custodian *derives*; nothing in
configuration can claim it.

A host that embeds whip can own the authentication fully. Such a host gives
resolved credentials to whip in the profiles of the providers. The
`WHIPPLESCRIPT_PROVIDER_PROFILES` variable names a JSON file that the host
writes. The file maps the name of a profile to a set of values. The name of the
profile is the declared `profile` of the agent, and `default` is the value for
each other profile. The values are
`{ provider, model, api_key | api_key_env, base_url?, max_tokens?, timeout_secs? }`.
When an entry matches, an owned turn uses the entry, and whip acquires no
credential. The sequence of the resolver above then becomes the fallback for a
standalone whip. An entry that a person configured but that is broken fails the
turn honestly. The system does not silently use the fallback. The `status`
subcommand names the active file of the profiles.

## Introspection and governance

### `agents`

```sh
whip [--json] agents [--root <workflow>] <workflow.whip>
```

The command lists each declared agent in a program, from the compiled IR. The
command gives the provider, the harness, the profile, the capacity, the
capabilities, the tools, and the skills of each agent.

### `mcp`

```sh
whip mcp list
whip mcp add <name> (--url <url> | --command <cmd> [--arg <a>]...) [--env K=V]... [--header K=V]...
whip mcp import <file>
whip mcp status <name>
whip mcp pin <name>
whip mcp sync <name>
whip mcp attest <name> --trust-annotations
whip mcp forget <name>
```

The command manages the registry of external MCP tool servers that the built-in
harness can call. The registry holds the evidence for each server. That evidence
is the pin, the attestation, and the role file. The registry does not hold the
requirement. A governance envelope holds the requirement, with a
`require mcp <rung>` statement.

- `list` reports each server with its derived trust rung and its transport. With
  the `--json` flag, each row has a `name`, a `rung`, a `transport`, a count of
  `pinned_tools`, and the `roles`.
- `add` registers a server. Use `--url` for the HTTP transport or `--command`
  with `--arg` for the stdio transport. A value of the form `env:NAME` in an
  `--env` or a `--header` option reads the environment variable `NAME` when whip
  connects, so the file holds a reference and not a secret. The command refuses
  a `http://` URL for a host that is not loopback, because the request carries
  the credentials of that server.
- `import` reads a `mcpServers` block, in the format that other MCP clients use,
  and registers each server in it. An import does not grant trust. Each server
  keeps its earlier evidence only when the transport does not change.
- `status` connects to the server, reports the tools that the server offers, and
  reports which tools carry an annotation. The command exits non-zero when the
  live manifest does not match the pin.
- `pin` freezes the manifest. The digest of each tool covers the name, the input
  schema, the description, and the annotations.
- `sync` re-pins a server after you review a change.
- `attest` records that you believe the self-reported annotations of a server.
  The command needs a pin first.
- `forget` removes a server from the registry.

For the trust ladder, for the grant syntax, and for the limits of what whip
enforces, read [Providers & packages](providers.md#whip-mcp-external-mcp-tool-servers).

### `providers`

```sh
whip [--json] providers [--root <workflow>] <workflow.whip>
```

This command is the view for an operator of each provider that a program needs.
The command collects the `provider` value of each declared agent, channel, and
source into one list with no duplicates. The command gives the items that
reference each provider.

### `skills`

```sh
whip [--json] skills [--root <workflow>] <workflow.whip>
```

The command lists each skill that the agents of a program declare. The command
gives the agents that declare each skill.

### `skill`

```sh
whip [--json] skill list
whip [--json] skill validate <SKILL.md|dir>
whip [--json] skill install <SKILL.md|dir>
```

The command manages the local control plane of the skills of the owned harness.
The `list` subcommand lists the installed skills. The `validate` subcommand
checks a `SKILL.md` file or a directory of such files. The `install` subcommand
adds one skill to the local store of the skills. The content addresses a skill.
A skill never grants authority.

### `gov`

```sh
whip gov <sign|verify|escalate|escalations|agent> [args]
```

This command is the surface for governance (DR-0026 and DR-0028). The `sign`
subcommand and the `verify` subcommand operate on signed governance envelopes.
The `escalate <request>` subcommand files a request with low integrity to the
log that the `WHIPPLESCRIPT_GOV_ESCALATIONS` variable names, for an
administrator to review. The `escalations` subcommand lists the requests. The
`gov agent` subcommand starts the loop of the governance agent, which has
privilege. The subcommand refuses to start without the privilege for governance.

### `infoflow`

```sh
whip infoflow
```

The command starts the interactive loop of the whip agent with no privilege
(DR-0026 and DR-0028). The command reads its commands from stdin. The
`check <file>` command runs the check of the information flow on a whip source.
The `escalate <request>` command files an escalation to governance. The `quit`
command exits.

The loop has no path to a signature for governance. The loop refuses a `sign`
command. The command has the name `whip infoflow` after a rename in one
direction from `whip agent`. There is no alias. Refer to the "Operator CLI"
section of `spec/std-agent.md`. The old spelling gives an error with a pointer
to this command.

### `coercion status`

```sh
whip [--json] coercion status
```

The command shows the resolved configuration of the `schema.coerce` provider.
The command gives the provider, the backend, the model, the source of the
credential, the level that made the selection, and the fingerprint. Use this
command to find the reason that a `coerce`, a `decide`, or a `prompt` statement
resolves to the fixture provider and not to a true model.

### `memory`

```sh
whip memory pools                       # list the workspace memory pools
whip memory entries <pool> [--limit <n>]  # show a pool's entries
```

These are read-only views of the memory store of the workspace. That store
supports the `learn` verb and the `recall` verb of `std.memory`. The
`WHIPPLESCRIPT_MEMORY_STORE` variable overrides the path of the store.

### `script`

```sh
whip script list [--script-manifest <path>]     # the pinned script capabilities
whip script verify [--script-manifest <path>]   # re-hash each pin; exit 1 on mismatch
```

These are read-only views of the pinned manifest of the script capabilities. The
manifest supports `std.script` and the hosted `exec <name> with ...` surface. The
`verify` subcommand computes the hash of each pinned script again. The
subcommand exits with a code that is not zero on each mismatch of the content.
This is a security check. The check makes sure that the scripts on the disk
still match the SHA-256 pins of their manifest.

### `verify-report`

```sh
whip verify-report [--entry-index <n>] \
  [--emit construct-graph|lowered-ir|artifacts] \
  <check-or-compile-or-artifacts-report.json>...
```

The command verifies the digests in a `check` report, a `compile` report, or an
artifacts report that a command emitted before. The command then derives the
verified artifacts of the report again. The `--entry-index` flag selects one
entry from a report with more than one entry. The `--emit` flag prints one
artifact that the report contains. The artifacts are the graph of the
constructs, the report of the lowered IR, and the set of the artifacts.

### `branch` (experimental, unreleased)

```sh
whip [--json] branch <subcommand> ...
```

The `branch` command and its companion the `stream` command support the
versioned workspace, which is the whip-native VCS. The surface is present and it
operates. But treat the surface as experimental, and expect a change. This is
the full set of the subcommands. Run `whip branch --help` for the flags of each
subcommand:

- **lifecycle** — `create`, `fork` (from a parent at an optional cut), `list`,
  `show`, `status`, `remove`, `discard`, `bind`, `reconcile`
- **content** — `write`, `read`, `ls`, `erase`
- **history** — `cut` (records a named point), `diff` (against a branch or a
  cut), `log`, `attribution`, `bisect` (`--good`, `--bad`, `--run`),
  `restore <branch> <cut>`
- **merge and selection** — `probe` (a dry run of a merge), `merge`,
  `conflicts`, `resolve <path> --ours|--theirs|--body`, `select <expr>`,
  `undo <expr>`, `transport <expr> --onto <target>`, `adopt-only <expr>`
- **operations and transport** — `ops`, `undo-op`, `export` (`--delta-have`),
  `import`, `digest`, `have`

### `stream` (experimental, unreleased)

```sh
whip [--json] stream <create|join|leave|archive|promote|list|show> ...
whip stream create <stream> [--name <label>]   # group review branches into a stream
whip stream join <stream> <branch>             # add a branch to the stream
whip stream leave <branch>                      # remove a branch from its stream
whip stream promote <stream>                    # promote the stream's work
whip stream archive <stream>                    # archive a finished stream
whip stream list | whip stream show <stream>    # inspect
```

A stream groups the `branch` items of a versioned workspace for a review. The
status of the `stream` command is the same experimental status as the status of
the `branch` command.

## Language reference index

For the examples and the semantics, refer to
[Language Reference](language-reference.md). This section is a compact index of
the constructs of the source.

### Top-level constructs

| Construct | Surface | Meaning |
| --- | --- | --- |
| Workflow | `workflow Name { ... }` or `workflow Name` | The runtime boundary that you can deploy. |
| Contract | `input name Type`, `output name Type`, `failure name Type` | The typed contract for the input, the output, and the failure of a workflow. |
| Include | `include "path.whip"` | The composition of a bundle of source. |
| Package/library import | `use std.memory` | Imports the library surface of a package by its name. |
| Class | `class Name { field Type }` | The schema of a typed fact and of a payload. |
| Enum | `enum Name { A B }` | A finite domain of strings. |
| Signal | `signal deploy.finished { field Type }` | The schema for the typed ingress of an external signal. |
| Harness | `harness coder: codex` | A named family of endpoints of a provider that `agent ... using coder` uses. |
| Agent | `agent name { profile "..."; capacity N; skills [...] }` | The logical target of a provider, and the metadata of the policy. |
| Coerce | `coerce fn(args...) -> Type { prompt """markdown ... """ }` | A declared effect that a coercion backend supports. |
| Channel | `channel name { provider local destination "#ops" }` | A named endpoint for messages. The endpoint supports the inbound `when message from` clause and the outbound `send via` statement. The provider must be `local`, `desktop`, `stdio`, or `fixture`. |
| Source | `source clock\|file\|http as name { ... observe as obs emit <signal> { ... } }` | An ingress source. The forms are a clock schedule, the lines of a `path` file, the occurrences of content of a `watch` file, and a GET-only http fetch. The optional `dedup <obs>.<field>` clause applies. The `emit` clause admits the observed input as a typed signal through the core for admission. An embedded manifest or a locked manifest of a package must contribute the kind of the provider. |
| File store | `file store name { root "..." allow read [...] allow write [...] }` | A policy boundary over a root of documents that a provider supports. The boundary applies to `read text`, `write text`, `import`, and `export`. |
| Tracker | `tracker name { provider builtin }` | A declared backlog of work items that is independent of a vendor. |
| Lease | `lease name { key Type slots N ttl 10m }` | A mutex or a semaphore with a limit. The scope is the workspace. |
| Ledger | `ledger name { entry Type partition by field retain 90d }` | A log that permits append only. A typed field partitions the log. The scope is the workspace. |
| Counter | `counter name { key Type cap N reset daily }` | A budget that a program consumes. The reset occurs at the boundary and not before. The scope is the workspace. |
| Pattern | `pattern Name<T> { ... }` | A fragment for reuse at compile time. |
| Apply | `apply Name<Type> as Alias { ... }` | The specialization of a pattern. |
| Assertion | `assert expression` | A deterministic check of a projection in the `dev` loop. |
| Gauge | `gauge name [on site] { judge via ... expect ... }` | A named dimension of quality: a judge and an optional bar. The system scores a gauge ambiently. The `whip improve` command optimizes a gauge. |
| Campaign | `campaign name { ascend ... reach ... guard ... sacrifice ... }` | Objective intent with a version: the division of the vector of the gauges. |

### Rule constructs

| Construct | Surface | Meaning |
| --- | --- | --- |
| Rule | `rule name ... => { ... }` | An atomic deterministic rewrite. |
| Fact match | `when Class as binding` | Binds a fact that no rule consumed. |
| Guarded match | `when Class as binding where expr` | Binds a fact only when a pure guard is true. |
| Started event | `when started` | Matches the initial `external.started` event. |
| Readiness | `when Class as item` or `when { ... }` | Matches facts and other deterministic conditions of a rule. |
| Availability | `worker is available` in a `when` clause or group | Matches the logical capacity and policy availability of an agent. |
| Agent turn | `when <agent> completed turn ... [as x]` | Matches an `agent.turn.completed` fact. A declared name of an agent filters to the turns of that agent. The generic word `worker` matches each agent. |
| Tracker readiness | `when <tracker> has ready issue as x` | Matches an item in a work tracker that a rule can claim. |
| Declared signal | `when deploy.finished as x` | Matches a typed external signal fact that a `signal deploy.finished { ... }` declaration declares. |
| General fact | `when fact <dotted.name> as x [where ...]` | The general form of readiness. The forms above are sugar for this form. |

### Rule body operations

| Operation | Effect/commit output |
| --- | --- |
| `record Class { ... }` | A new fact. |
| `record Class from binding { ... }` | A new fact with copied fields. |
| `done binding` | Marks a matched fact as consumed. The old `consume binding` alias is removed and is now a check error. Use `done`. The `consume <counter> for <key> amount <n>` statement is a separate verb for a counter, and that verb is current. |
| `done binding -> record ...` | Consumes a fact and makes the replacement fact atomically. |
| `tell agent ... [timeout <dur>] as turn` | An `agent.tell` effect. |
| `prompt "..." [using provider] as result` | A free-text prompt effect that a provider supports. The result has the shape of a string. |
| `coerce fn(...) as result` | A `schema.coerce` effect. The keyword in the source is `coerce`, and the kind of the effect is `schema.coerce`. |
| `decide "..." -> { ... } as result` | An inline typed `schema.coerce` effect. |
| `exec "<command>" as result` | An `exec.command` effect in the dev profile. The effect needs a `use std.script` statement and a `WHIPPLESCRIPT_EXEC_ALLOW` value that is not empty. The two items seed the `script.raw` capability. The effect makes `exit_code` and `stdout` available. |
| `exec <capability> with <record> -> Type as result` | A hosted `exec.command` effect. The effect needs the `script.<capability>` capability, typed JSON on stdin, verification of the SHA-256 value of the manifest, and typed ingestion of stdout. |
| `file issue into <tracker> { ... }` | A `tracker.file` effect. |
| `claim <item> [as x]` | A `tracker.claim` effect. An item that a different rule already claimed is a failure that you can branch on. |
| `release <item>` | A `tracker.release` effect. |
| `finish <item> [{ summary ... }]` | A `tracker.finish` effect. |
| `read text from <store> at <path> as x` | A `file.read` effect on a declared `file store`. |
| `write text to <store> at <path> { body ... [mode ...] } as x` | A `file.write` effect on a declared `file store`. |
| `import <jsonl\|json\|csv> <Schema> from <store> at <path> as x` | A `file.import` effect. The effect decodes structured rows into typed facts. |
| `export <jsonl\|json\|csv> <Schema> to <store> at <path> { [where ...] mode ... } as x` | A `file.export` effect. The effect writes typed rows to a file. |
| `redact <binding> keep [..] as <out>` | Projects a binding with a record type onto a subset of the fields. The projection operates at the level of the type and removes the fields at run time, with a refinement of the IFC label for each field. |
| `then <binding> <- <effect ...>` | The sugar for a sequential chain. The statement desugars to nested `after` blocks for success. A step that fails fails the instance automatically and names the binding. |
| `during <condition> { ... } on lapse [as <x>] { ... }` | A region of a pinned progression. The steps of the body run while the condition is true. When the condition breaks while the region still owes work, the region lapses: the runtime cancels the work in operation and runs the mandatory arm. The optional `as <x>` binds the progress view. Refer to chapter 16 of the manual. |
| `until <condition> { ... } on lapse [as <x>] { ... }` | The opposite polarity of the `during` region. The steps of the body run while the condition is false, and the region lapses when the condition becomes true. One region per rule in v1. |
| `emit milestone "<name>" { ... }` | Publishes a typed milestone. A parent observes the milestone with an `after child reaches "<name>"` arm during the run. |
| `send via <channel> { text ... }` | An outbound message on a declared channel (std.messaging). |
| `timer <duration> as x` | A `timer.wait` effect that completes when the duration is due. |
| `timer until <time> as x` | An absolute `timer.wait` effect that completes at a typed instant or after a typed instant. |
| `cancel <binding>` | Cancels a pending effect, and the cancel operation is terminal. For an effect that runs, the statement requests a cancel operation. |
| `call capability for value as result` | A `capability.call` effect. |
| `emit signal <name> to <instance> { ... } as x` | A `signal.emit` effect. The effect injects a typed signal into a different instance. |
| `acquire <lease> for <key> as x` | A `lease.acquire` effect with the branch outcomes `held` and `contended`. |
| `release <lease-binding>` | A `lease.release` effect. |
| `append Type { ... } to <ledger> as x` | A `ledger.append` effect. |
| `consume <counter> for <key> amount <expr> as x` | A `counter.consume` effect with the branch outcomes `ok` and `over`. |
| `invoke Workflow { ... } as child` | A `workflow.invoke` effect. |
| `after effect succeeds/fails/completes` | A dependency branch with the scope of a terminal status. |
| `case expr { Pattern => { ... } }` | A deterministic branch on a finite domain. |
| `complete output { ... }` | A `workflow.completed` event and the terminal completed state. |
| `fail failure { ... }` | A `workflow.failed` event and the terminal failed state. |

## JSON contracts

The [JSON reference](json-reference.md) records the values of the statuses, the
types of the events, the output of the inspection commands, the output of the
coordination commands, the metadata of the providers, and the shapes of the
manifests of the artifacts.

## Rust APIs

The APIs of the Rust crates are interfaces for a contributor with internal
stability. These APIs are not the public CLI and not the JSON contract. Refer to
the [Rust API reference](rust-api.md).

## Formal and release checks

These are the usual checks at the root of the repository:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/check-formal-models.sh
scripts/check-tla-models.sh
scripts/check-e2e.sh
scripts/check-release-readiness.sh
```

The `scripts/check-formal-models.sh` script runs the Maude checks and the
wrapper for the TLA check. The `scripts/check-tla-models.sh` script runs the
type check of Apalache and the safety check with a limit. The
`scripts/check-e2e.sh` script runs the deterministic integration tests that use
the fixture provider.
