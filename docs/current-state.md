# Current state

WhippleScript is a pre-1.0 product. WhippleScript is good for durable
orchestration of agents, on your machine and on the edge. But WhippleScript is
not yet a stable dependency for production.

These documents apply to the `0.2.1` release. The public release line started at
`0.1.0`, which put the earlier internal 0.2, 0.3, and 0.4 development lines
together into one cut with the full set of features. This release is the v0.2
milestone. The number is `0.2.1` and not `0.2.0` because a tag with the name
`v0.2.0` was already published under the earlier ladder. To pin the exact
flags of the CLI, the exact fields of the JSON, or the exact behavior of the
configuration of a provider, use the documents from the applicable Git tag. The
`whip --help` command prints the version and one `release` label for the
implementation stage. That label is not a different compatibility version.

## Sufficiently stable to use

- The authoring loop. The loop is the `check` command, the `compile` command,
  the `run` command with the fixture provider, and the commands for inspection.
  Those commands are `status`, `log`, `facts`, `effects`, `runs`, `evidence`,
  `diagnostics`, and `trace --check`.
- The execution model. The model has durable facts, events, effects, atomic
  commits of the rules, dependencies between the effects, leases, and traces
  that you can replay.
- The static checks on liveness. Each workflow must get to `complete` or to
  `fail`, and the `@service` tag is the exception. Some part of the program must
  supply each read of a rule, and the `@external` tag is the exception.
- Review by a person through the tracker. A rule files an issue with a
  `file issue into <queue>` statement. A person works the issue with the
  `whip issue` command. A rule then reacts to the finish operation on the issue.
- Sequential chains with `then`. A chain desugars to nested `after` blocks. The
  `whip check` command shows the result.
- Pinned progressions. A firing that commits runs to its completion on the
  bindings that admitted the firing. A revision completes under the body that
  admitted the firing. This feature also has the `during` region and the `until`
  region, the mandatory `on lapse` arm, and the `whip progressions` command and
  the `whip progression cancel` command for an operator.
- Governance of the information flow. A signed envelope puts labels on the true
  resources, for confidentiality and for integrity. The `whip check` command
  proves the invariants for each resource and prints the guarantee report. The
  report has the trusted surface with the `carries:` provenance for each
  crossing, the principals that are vouched writers, and the provenance of the
  facts. A crossing is a `declassified` coercion or an `endorsed` coercion with
  a source mark, under a grant. The output of an effect is a governed writer,
  and the `from` clearance of its executor vouches for the writer.
- The improve subsystem. The subsystem has the `gauge` dimensions of quality
  with ambient scores. The subsystem has the `pin`, `suppose`, and `settle`
  commands with marks and paired regeneration. The subsystem has the `campaign`
  declaration that drives the `whip improve` command, with a holdout set, spend
  caps that park work, and the reopener for a contradiction. The subsystem has
  durable precedents through the `whip answer` command.
- The tools for an author. The tools are the `whip fmt` command, which is
  idempotent, the `whip lint` command, which has analyses with zero false
  positives, and the `whip lsp` command, which uses JSON-RPC over stdio and
  supports definitions across files.
- Work queues with the `builtin` tracker. The verbs are `file`, `claim`,
  `release`, and `finish`. The readiness pattern is
  `when <tracker> has ready issue`. The `whip issue` family of commands is also
  available.
- Time effects. These are the `timeout` clause, the `timer` statement, and the
  `cancel` statement. These effects fire on a worker pass.
- An inline `decide` decision, a `case` statement on a union of string literals,
  the general `when fact <dotted.name>` readiness form, a raw `exec` command in
  the dev profile, and a hosted script capability. The
  `WHIPPLESCRIPT_EXEC_ALLOW` variable makes the allow-list for a raw `exec`
  command. A manifest with a SHA-256 pin supports the hosted
  `exec <name> with <record> -> Type` statement.
- Concurrent execution of the effects. A worker pass runs its ready set on a
  thread pool with a limit. The `WHIPPLESCRIPT_WORKER_CONCURRENCY` variable sets
  the size. Thus a fan-out of agent turns or of `coerce` calls runs in parallel,
  and `agent { capacity N }` has a meaning at run time.
- The surface of the messaging constructs. The outbound statement is
  `send via <channel>`. The inbound clause is
  `when message from <channel> as msg`, which binds the built-in `Message`
  schema. The bindings drive the local providers. The providers are `local`,
  which is a mailbox in a file with a poll operation on the inbox and which you
  examine with the `whip mailbox` command; `desktop`, which is an outbound-only
  native notification; `stdio`; and `fixture`, where the `whip message` command
  injects an inbound message. Live delivery through Slack or email stays
  deferred.
- The management of the credentials. The commands are `whip auth status` and
  `whip auth set <openai|anthropic> <key>`. These commands store the credentials
  of a model for the native `coerce` path. Only the owner can read the
  configuration.
- The controls for the lifecycle. The commands are `pause`, `resume`, `cancel`,
  and `retry`. The `whip revise` command revises a workflow of an instance that
  is not terminal.
- Restorable context. The `whip checkpoint` command and the `whip restore`
  command rewind the state of the files, the transcript of the agent, and the
  position in the event log together, as one cut. The commands check the
  coherence of the cut. The restore operation does a full reconcile operation
  and makes an automatic checkpoint of the head first. The commands use native
  file I/O only. Refer to [Runtime & operations](runtime-operations.md).
- Acceptance fixtures through the `whip accept` command, and reports of the
  assertions that a tag filters. Use these to validate a workflow in CI.

"Sufficiently stable" means that the implementation in the repository and the
tests hold. This is not a promise about semver. The syntax, the flags of the
CLI, and the names of the fields of the JSON can still change between releases.

## Cloud runtime

The same kernel for the evaluation runs with no change in a Cloudflare Durable
Object wasm isolate. The isolate is sans-IO: its only async primitive is
`fetch`, and each effect that uses HTTP is a step machine that can resume. Such
a machine survives the eviction of the isolate. The host of the DO runs the same
scheduler of the instances, over the synchronous SQLite of the DO. A timer fires
through an alarm of the DO. The credentials of a provider come from the secrets
of the DO. The `whip deploy` command deploys a workflow to a Worker and a DO on
the edge, in one operation. A Class-A compute plane exists. That plane is the
`whip executor` sidecar over a `whip-executor/1` protocol. To use the plane, do
a follow-on step of the configuration. The plane is not on by default. Refer to
[Runtime & operations](runtime-operations.md) for the full cloud section.

## Experimental

- The owned brokered harness (`provider owned`, DR-0024). Whip runs the tool-use
  loop of the agent itself. Whip executes each file tool that the model
  requests. The loop settles to one `agent.turn.<status>` fact.

  These parts are in place. The file tools operate over the boundary of the file
  store. A live client for a model is available for OpenAI and Anthropic,
  through the `WHIPPLESCRIPT_HARNESS_*` variables, with a fallback to a fixture
  with no credential for CI. The envelope that the system applies has a budget of
  steps for each turn that you can configure, and a durable lease on the
  workspace. A `bash` tool operates in a sandbox. That tool is the in-isolate
  Bashkit virtual shell over the file surface of the workspace, with no reach to
  the OS and no reach to the network. A `with access to command { run }` grant
  gates the tool. Tracker tools operate with a gate on the capability. Those
  tools are `list_todos`, `add_todo`, and `update_todo`, over the durable work
  tracker. A call that changes data uses a `with access to tracker { ... }`
  grant. The context compacts on a long turn, and the compaction affects the
  projection only, because the durable stream is complete. A turn also resumes
  after a crash, because the system persists the transcript of the turn after
  each step and a recovered turn continues from that projection.

  The delegating adapters for Codex and Claude are now optional Cargo features.
  The owned harness is the built-in path.
- The adapters for a native provider. Codex and Claude are the validated
  delegating adapters. Credentials gate their behavior for a cancel operation,
  for an artifact, and for a recovery. Credentials also gate live execution
  against the true SDKs of the providers.
- The `openai-generic` family of provider. This family covers each endpoint that
  is compatible with OpenAI. The endpoints are a local Ollama instance, a local
  vLLM instance, and an aggregator. The configuration is a base URL, a model,
  and a reference to a key. A validation against a local endpoint succeeded. The
  family is not yet fully stable.
- A native `coerce` statement against a true model, through the OpenAI Responses
  API or the Anthropic Messages API. The logic for the request and the response
  is built and tested. But you must select a live call with the
  `WHIPPLESCRIPT_COERCE_PROVIDER` variable, and a credential gates the call. The
  fixture path is the default.
- Live messaging providers for Slack and email, which supply inbound `Message`
  facts.
- Access to the network. An `http source` fetches an external URL with the GET
  method only. A policy for SSRF and egress limits the fetch. The policy permits
  http and https only. The policy blocks a private address and a loopback
  address. The `WHIPPLESCRIPT_HTTP_SOURCE_ALLOW` variable gives the allowlist of
  hosts. The results appear in the `emit` clause of the source. A web *search* is
  a design that is deferred. The project did not ship a web search.
- The manifests of the packages and the formats of the configuration of a
  provider.
- The prebuilt binaries of a release. An install from source is the reliable
  alternative.

## Recommended use today

Prototype the orchestration on your machine and validate the orchestration
there. Route the tasks to the logical agents. Add the gates for a review and an
approval. Use the fixture provider to test the branches for a retry and a
failure. Then examine the durable record. You can then deploy the same workflow
to the edge with the `whip deploy` command. Refer to the Cloud runtime section
above. Treat each run against a true provider as an experiment with supervision.
