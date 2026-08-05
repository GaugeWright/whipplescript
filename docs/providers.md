# Providers & packages

A workflow describes the policy for coordination. A provider and a package are
the method that gets that policy to a true agent, tool, and service. The source
code names the logical agents and the capabilities. The runtime records durable
effects. A worker executes those effects through a provider. The output of a
provider returns as events, facts, runs, and evidence.

## The fixture provider

The fixture provider completes an effect deterministically and on your machine.
Use the fixture provider for development, for the tutorials, for the tests, and
for the design of a workflow. The provider uses the full durable lifecycle of an
effect and needs no credential:

```sh
whip --store .whipplescript/dev.sqlite \
  run examples/provider-language-e2e.whip \
  --provider fixture --until idle --json
```

The flags for the outcome of the fixture force a terminal branch. Thus you can
test the handling of a failure. The flags are `--fail`, `--timeout`, and
`--cancel`, on the `run` command and on the `worker` command.

## Binding agents to providers

A workflow binds each logical agent to a family of provider in the source:

```whip
agent implementer {
  provider codex
  profile "repo-writer"
  capacity 2
  capabilities ["agent.tell"]
  skills ["whipplescript-author"]
}
```

- The `provider` field names the family. The families are `owned`, `codex`,
  `claude`, `fixture`, and `command`. The `command` family is a delegating
  wrapper around an arbitrary command, for the dev profile only.
- The `profile` field describes the authority, such as `repo-reader` or
  `repo-writer`.
- The `capacity` field limits the concurrent turns.
- The `capabilities` field lists the operations that you can ask the agent to
  do.
- The `skills` field attaches bundles of context to the turns of the agent.

A `tell implementer ...` statement makes an `agent.tell` effect. A worker
executes the effect through the item that the provider configuration binds to
`codex`. A change from the fixture provider to a true provider changes the
configuration and not the rules.

Sometimes one family of provider needs more than one configured endpoint. In
that condition, declare the named endpoints with a `harness` declaration. Then
bind the agents with an `agent ... using harness` declaration. A configuration
of a harness binds by the name of the harness.

## Owned harness (`provider owned`)

The `codex` family and the `claude` family **delegate** the full agent turn to
the harness of the provider. Whip captures a summary and redacts the summary.
Whip cannot truly apply a limit on the operations of the turn.

The **owned** harness runs the tool-use loop itself. The model requests a tool.
*Whip* executes the tool. Whip gives the result back to the model. The loop
continues to one terminal. Whip is the executor. Thus a primitive for
coordination becomes an envelope on the turn that whip *applies*. The primitive
is not advisory metadata.

The internal design record for this harness is DR-0024.

```whip
agent helper {
  provider owned
  profile "repo-writer"
  capacity 1
}
```

The system records a call to a tool in a turn as **evidence**. The system does
not record such a call as a fact that a rule can match. Only the single
`agent.turn.<status>` terminal becomes a fact. Thus a
`when <agent> completed turn` clause and an `after <turn> succeeds` block
operate exactly as they operate with a delegating family.

The current scope is **experimental**:

- The tools are `read`, `write`, `edit`, `grep`, `find`, `ls`, `recall`, and
  `bash`. The workspace tools execute through the path policy of the file store.
  `recall` pages a content-addressed result when another tool's output was
  truncated. A path that is absolute or that uses `..` cannot leave the store.

  The file tools are **deny by default**. The harness offers a file tool only
  when the turn carries the applicable grants of a file store. The `edit` tool
  needs a read grant and a write grant. When an IFC governance envelope is
  active, that envelope must also govern the granted file stores before the
  system admits the turn.

  A `tell ... requires [...]` list makes the surface of the owned tools more
  narrow. The list applies to the known capabilities of a harness, which are
  `repo.read`, `repo.write`, `command.run`, the `tracker.*` capabilities, and
  `workflow.invoke`. The scheduler already needs the target agent to declare
  those values.

  The harness offers the `bash` tool only with a `with access to command { run }`
  grant. The tool runs only in two conditions together. The set of the profile
  and the required capabilities permits `command.run`, and the turn carries that
  grant. The tool then executes in the **in-isolate Bashkit virtual shell**
  (DR-0039), over the governed file surface of the workspace. The shell is
  **not** a true OS shell. There is no `fork` operation, no `exec` operation, no
  ambient file system, and no ambient network.

  The usual features of a shell operate. These features are pipes, substitution,
  redirection to a file in the workspace, and a fixed set of builtin commands.
  But these features cannot get outside the workspace. Each file that the
  command reads, writes, or deletes crosses the **same policy boundary of a
  labeled store as the file tools**. That boundary is the read globs and the
  write globs of the granted stores. A path outside the workspace does not exist
  for the tool. When an IFC governance envelope is active, that envelope must
  also govern the `command` resource. The interpreter has no reach to the OS.
  Thus there is no allow-list of commands to configure. The sandbox and the
  policy of the workspace ARE the boundary that the system applies.
- The tracker tools are `list_todos`, `add_todo`, and `update_todo`. The harness
  offers these tools only when you set
  `WHIPPLESCRIPT_HARNESS_TRACKER=<tracker>`. The agent then participates in the
  durable work tracker. The agent files items and updates items that the rules
  of the workflow observe.

  The `list_todos` tool stays read-only and has no gate. The harness offers and
  executes a tool that changes data only when the turn delegates the authority
  of the tracker. The `add_todo` tool needs a
  `with access to tracker { file }` grant. The `update_todo` tool needs the
  `claim`, `finish`, or `release` grant for the applicable change of status. An
  `update` grant is an alternative.

  A registered profile can make this authority more narrow with
  `tracker.file`, `tracker.claim`, `tracker.finish`, `tracker.release`,
  `tracker.update`, or `tracker.write`. When an IFC governance envelope is
  active, an authority that changes a tracker also needs the envelope to govern
  the `tracker` resource.

  Under the refined I3 rule, these tools write shared *state* of a tracker. They
  never write a fact that a rule can match. The system attributes an `add_todo`
  item to the agent with `source: "agent"`.
- The sub-workflow tools follow the internal design record DR-0025.
  A workflow with the `@tool` tag becomes a typed tool for an agent. The `input`
  contract of the workflow is the JSON schema of the tool. The model can
  **invoke the tool synchronously** during a turn. The call blocks the turn
  until the sub-workflow gets to its terminal. The call then returns the
  `output` payload of the sub-workflow. A terminal that is not `completed`
  appears as an error of the tool.

  A `@tool` workflow must pass a **convergence check**. The workflow must
  terminate. Thus the workflow cannot have the `@service` tag. The workflow
  cannot have readiness on an external signal, on the `@external` tag, or on an
  inbound message. In v1, the workflow also cannot have a nested `invoke`
  statement. Thus the synchronous block has a limit, and a proof shows that the
  block cannot continue for an unlimited time.

  This mechanism is brokering. The mechanism is not a call to a shell. The
  sub-workflow runs through the runtime with first-class lineage between the
  parent and the child, durable events, and recovery after a crash. The
  sub-workflow is not an opaque subprocess.

  The selection has two sides. A workflow selects the mechanism with the `@tool`
  tag. An agent gets a **grant** for specified tools with a
  `tools [WordCount, OpenPr]` field. That field is the surface for the selection
  in the program, and the `whip check` command checks the field. A grant for a
  workflow with no `@tool` tag is a compile error.

  A granted name resolves against the same bundle of the program or against a
  package that a `use` statement imports. The operator override
  `WHIPPLESCRIPT_HARNESS_TOOLS=<path>[,<path>…]` also lists the `@tool` sources
  outside the tree for a turn. The system merges that list with the grant, and
  the grant wins when a name is the same.

  A registered profile and a `tell ... requires [...]` list can make the surface
  of the workflow tools that the model sees more narrow, with the
  `workflow.invoke` capability. If the resolved policy of the profile and the
  required capabilities has no such capability, the system refuses a direct call
  at the dispatch operation.

  An import of a `@tool` workflow across packages also needs the active IFC
  envelope to govern the invoke door of the package. That door is
  `invoke:<package>/<tool>`. The envelope must govern the door before the
  harness offers the tool.

  A package exports a `@tool` workflow with two operations. The package ships
  the source of the workflow. The package lists the workflow in the manifest, in
  the form `"workflow_tools": [{ "name": …, "source": … }]`. The contract of the
  package then carries an **attestation** of the eligibility for convergence.
  The attestation is the derived input schema and output schema of the tool. The
  contract also carries a surface of information flow that has the membrane door
  `invoke:<package_id>/<tool>` for the invoke operation of the package. Under a
  governed envelope, the envelope must govern that invoke door before the system
  can check the imported tool or offer the tool to the model.

  The system checks the grant of a consumer against the contract. The system
  then drives the tool from the source that the package ships. Refer to
  `examples/subworkflow-tool-consumer.whip`. That example grants the `EchoText`
  tool of the `toolkit` package.
- The workspace of the turn comes from the
  `WHIPPLESCRIPT_HARNESS_WORKSPACE` variable. The default is the current
  directory.
- To drive the loop with a **live** model, set the
  `WHIPPLESCRIPT_HARNESS_PROVIDER` variable to `openai` or to `anthropic`. Also
  set the `WHIPPLESCRIPT_HARNESS_MODEL` variable. The system uses the
  credentials from the resolver for the coercions. The sequence is the
  environment variable, then the `whip auth` store, then the Codex OAuth token.
  The other controls are `WHIPPLESCRIPT_HARNESS_BASE_URL`,
  `WHIPPLESCRIPT_HARNESS_MAX_TOKENS`, and
  `WHIPPLESCRIPT_HARNESS_TIMEOUT_SECS`.

  If you set no variable, a deterministic **fixture** client with no credential
  drives the loop. Thus the `run` command and CI need no credential. The
  `WHIPPLESCRIPT_OWNED_FIXTURE_TOOL=read:<path>` variable makes the fixture
  client use one call to a tool.
- A configuration of a provider can list the `profile_ids` field. A list that is
  not empty is an allow-list of endpoints. The system applies the allow-list
  before it starts the provider. If the profile of an agent does not match, the
  effect stays in the `blocked` state and can recover. The category is
  `provider_config`.
- The envelope of a turn has a budget of steps of the model for each turn. The
  variable is `WHIPPLESCRIPT_HARNESS_MAX_STEPS`, and the default is 16. This
  budget limits the loop. The turn also holds a durable lease on the workspace
  for its duration. Thus a workspace with contention blocks, and the block can
  recover. The turns do not race.

  The key of the lease is the **unit of work**, which is the invocation at the
  top level. The key is not the individual turn. Thus a turn that synchronously
  invokes a sub-workflow tool shares the lease of its own root, and the lease is
  re-entrant. Such a turn does not deadlock against itself. Only a *different*
  unit of work contends. This behavior follows the internal design record
  DR-0025.
- The harness compacts the working context of the model on a long turn. The
  harness changes an old result of a tool into a reference. The harness keeps
  the System message, the first instruction, and a recent window without a
  change. This operation touches only the data that the model reads again. The
  durable stream of the observations is complete and does not change.
- The harness persists the transcript of the turn after each step. This gives
  recovery after a crash. If a turn stops, a later worker pass continues the
  turn from that projection. The harness discards a final call to a tool that
  has no result. Thus the model decides again. The harness does not run the turn
  again from the start.
- One refinement is still open: full confinement of the writable root at the
  level of the OS, for the `bash` tool. The allow-list is the current boundary.

```sh
whip --store .whipplescript/owned.sqlite \
  run examples/owned-harness-demo.whip --provider owned --until idle
```

## Credentials and configuration

The source never holds a credential. The configuration of a provider binds an
identifier of a provider at the level of the source to a concrete surface and a
*reference* to a credential:

```json
{
  "provider_id": "codex",
  "provider_kind": "codex",
  "surface": "codex_app_server",
  "credentials_ref": "env:OPENAI_API_KEY"
}
```

The `credentials_ref` value is the name of an environment variable, a handle of
a keychain, or the identifier of a secret. The value is never a credential.
Validate a configuration with this command:

```sh
WHIPPLESCRIPT_PROVIDER_CONFIGS=examples/provider-configs/native/native.example.json \
scripts/check-native-provider-configs.sh
```

The checker records results that it redacts. The checker never prints the value
of a secret, a prompt, or a raw response of a provider.

### Spend prices (`prices` block)

A file with the configuration of a provider can carry a `prices` array at the
top level. That array is the table of the prices for the spend. The improve
subsystem uses the table for the `--spend-cap` flag and for the `std.spend`
gauge:

```json
{
  "providers": [...],
  "prices": [
    {"provider": "anthropic", "model": "claude-sonnet-5",
     "input_per_mtok_usd": 3.0, "output_per_mtok_usd": 15.0,
     "cache_read_per_mtok_usd": 0.3, "cache_write_per_mtok_usd": 3.75}
  ]
}
```

The two rates for the cache are optional. A provider bills the traffic of the
prompt cache at rates that are different from the rates for fresh input.
Anthropic gives a large discount on a cache *read* and adds a charge for a cache
*write*. OpenAI gives a discount on cached input and does not bill a write. The
system normalizes the usage into separate buckets for each turn. The buckets are
uncached, cache read, and cache write.

An entry with no rates for the cache prices the traffic of the cache at the
**input** rate. That rate is a conservative overestimate for a read. Thus a
table that is not complete can only count too much toward a spend cap. Such a
table can never count too little. The built-in `std.cache_hit` gauge reads out
the hit rate of the cache. The rate is the tokens that the provider read from
the cache divided by each token on the input side. The gauge is available when
the provider reports the use of its cache.

A rate is in USD for each million tokens, for each provider and model, with the
input side and the output side separate. The prices are in the **configuration
only**. Whip ships no built-in rate. A built-in rate that is not current would
give an incorrect price for the spend, and the system would give no message.

Usage with no matching entry records honestly as `unpriced` with a cost of 0.
Such usage is visible in the events of the spend, and such usage cannot bind a
spend cap. The system applies a price at the time of the record. The system
never applies a price to the history again. The maintained example is at
`examples/provider-configs/native/native.example.json`. Verify the rates of that
example against the current price sheet of your provider before you depend on
the cap.

> **A model with no price under a `--spend-cap` flag.** The cap binds only the
> *priced* cost. Thus a model with a cost and with no entry in the `prices`
> array would let the cap never bind, and the system would give no message. A
> campaign that spends under a cap while some usage has no price now ends with a
> **warning**. The record also has a `campaign.spend_cap_unpriced` event, and
> the warning names the gap.
>
> This condition is most important for an arbitrary `openai-generic` endpoint.
> Add a `prices` entry for the model to make the cap enforceable. For a local
> model that is truly free, such as Ollama or a local vLLM instance, add an
> entry with `input_per_mtok_usd: 0` and `output_per_mtok_usd: 0`. That entry
> declares the model free and stops the warning.

## Native providers

The native adapters for Codex and Claude are experimental. The setup, the
behavior of a cancel operation, the capture of an artifact, and the shape of the
evidence can change.

The Codex adapter and the Claude adapter are now **optional Cargo features**.
The features are `codex` and `claude`, and the two features are on by default.
The owned harness is the built-in path. A smaller binary can omit the delegating
adapters:

```sh
# whip without the Codex/Claude delegating adapters
cargo install --path crates/whipplescript-cli --no-default-features
```

A workflow that selects `provider codex` or `provider claude` against a binary
with no such feature fails the turn. The message is clear: the provider is not
built into this whip. The system does not use a different provider silently.

| Provider | Surface | Identity | Cancellation | Evidence |
| --- | --- | --- | --- | --- |
| Codex | the JSON-RPC of the app server | the identifier of the thread and the turn | `turn/interrupt` | notifications, summaries of the tools and the approvals, metadata of the diffs |
| Claude | the sidecar of the Agent SDK | the identifier of the session | a cooperative cancel operation of the SDK | the messages of the stream, summaries of the hooks and the tools, the usage |

After a crash leaves a native run in an interrupted state, the
`whip recover <instance>` command reconciles the run. The command uses the
evidence of the provider that the system persisted.

The model for an agent turn is never fixed in the code. For the surface of the
Codex app server, the system resolves the model in this sequence. First, the
`default_model` value in the configuration of the provider. Then the
`WHIPPLESCRIPT_CODEX_APP_SERVER_MODEL` variable. Then the `model` value in
`~/.codex/config.toml`. If no source sets a model, the turn fails with a clear
message: no model is configured. The system does not guess a default.

### Provider errors in failure diagnostics

The system redacts the shape of the native evidence. The system records a prompt
and the output of a model as a JSON *shape* only. The system never records the
values. Thus the content of a turn never enters the store of the run.

An error of the **control plane** of a provider is the deliberate exception.
Sometimes a turn fails for an operational reason. The reasons are an exceeded
limit on the usage, a rejected authentication, and a model that the system did
not find. Such a reason is operational metadata and not the output of a model.
Thus the reason crosses the boundary of the redaction into the diagnostic of the
failure and into the summary of the evidence of the effect.

The system limits the reason to 300 characters. The system also passes the
reason through the same redaction of the secrets as each other item. Thus a
message about a failure of the authentication can give the cause without an echo
of a token. Read the `whip diagnostics <instance>` output and the
`whip effects <instance>` output on an agent turn that failed, to see the
reason.

You must select the smoke tests against a true provider:

```sh
WHIPPLESCRIPT_E2E_REAL_PROVIDERS=1 \
WHIPPLESCRIPT_REAL_PROVIDERS=coerce,codex \
scripts/check-real-providers.sh
```

The reports go to `target/real-provider-smoke-report.md` and to
`target/real-provider-reports/<provider>.json`. The strict validation of a
native provider and the destructive tests of a provider have more gates. Refer
to [troubleshooting](troubleshooting.md#native-provider-strict-mode-fails).

## Native coerce (real model decisions)

By default, a `coerce` statement and a `decide` statement run against the
deterministic fixture. Thus the `run` command, the `worker` command, and CI need
no credential. To run a decision with a true model, select the model with
environment variables:

```sh
# OpenAI (Responses API, JSON-schema structured output)
WHIPPLESCRIPT_COERCE_PROVIDER=openai OPENAI_API_KEY=sk-... \
  whip run workflow.whip --provider fixture

# Anthropic (Messages API, single forced tool)
WHIPPLESCRIPT_COERCE_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-api... \
  whip run workflow.whip --provider fixture
```

The system builds the output JSON Schema from the declared output type of the
`coerce` declaration. The system sends the schema as the native constraint of
the provider for structured output. Thus the system parses the result directly
into the typed value. These controls are useful:
`WHIPPLESCRIPT_COERCE_MODEL`, `WHIPPLESCRIPT_COERCE_BASE_URL`,
`WHIPPLESCRIPT_COERCE_MAX_TOKENS`, and `WHIPPLESCRIPT_COERCE_TIMEOUT_SECS`.

These are the credentials:

- **OpenAI** uses the `OPENAI_API_KEY` variable against `api.openai.com`. With
  no key, OpenAI uses the Codex OAuth token in `~/.codex/auth.json`. That token
  routes to the codex backend of the ChatGPT plan, at
  `chatgpt.com/backend-api/codex/responses`, with SSE. The model comes from the
  `WHIPPLESCRIPT_COERCE_MODEL` variable or from `~/.codex/config.toml`. A
  validation confirmed that this path obeys structured outputs. This path bills
  your ChatGPT plan. OpenAI publicly permits the use of the codex endpoint.
- **Anthropic** needs an API key from the console. The key has the form
  `sk-ant-api*`. Supply the key with the `ANTHROPIC_API_KEY` variable or with
  the `whip auth set anthropic` command. The system rejects an OAuth token of
  Claude Code, which has the form `sk-ant-oat*`. The message is clear. The reuse
  of such a token for the API is not clearly permitted by the terms.

If you set the provider and no credential resolves, the coerce effect fails with
a clear message. The system does not use a fixture silently.

## OpenAI-compatible & local models (Ollama, vLLM, OpenRouter, Groq, …)

Each system that speaks the OpenAI Chat Completions wire format at
`/v1/chat/completions` operates through the **`openai-generic`** provider. The
systems are the local runtimes Ollama, LM Studio, vLLM, and llama.cpp. The
systems are also the hosted gateways OpenRouter, Together, Groq, Fireworks,
DeepSeek, and Azure OpenAI. There is one provider, and the `base_url` value
selects the system.

> **The `base_url` value must contain the segment for the version of the API.**
> Usually that segment is `/v1`. The `openai` provider and the `anthropic`
> provider are different. For those providers, the base is the host alone, and
> whip appends `/v1/...`. The `openai-generic` provider appends only
> `/chat/completions`. This behavior follows the convention of the OpenAI SDK,
> where the version is in the `base_url` value. Thus use
> `http://localhost:11434/v1`. Do **not** use `http://localhost:11434`.

### Coerce / decide (structured output)

```sh
# A local Ollama model making a typed `coerce` decision:
WHIPPLESCRIPT_COERCE_PROVIDER=openai-generic \
WHIPPLESCRIPT_COERCE_BASE_URL=http://localhost:11434/v1 \
WHIPPLESCRIPT_COERCE_MODEL=llama3.1:8b \
OPENAI_API_KEY=ollama \
  whip run workflow.whip --provider fixture --until idle
```

The `OPENAI_API_KEY` variable carries the bearer token. An endpoint that does
not check the token, such as Ollama, accepts a value that is not empty. Confirm
the resolved configuration with the `whip --json coercion status` command.

The system sends the declared output type of the `coerce` declaration as a
`response_format: json_schema` constraint. An endpoint that supports the
constraint returns JSON that agrees with the schema. The endpoints are Ollama,
vLLM, and OpenAI. The system parses that JSON directly into the typed value.

### Agent turns (owned harness)

Point the [owned harness](#owned-harness-provider-owned) at the same endpoint.
Use a file with the **profiles of the providers**. The
`WHIPPLESCRIPT_PROVIDER_PROFILES` variable names the file. The declared
`profile` of the agent keys the file, and `default` is the value for each other
profile:

```json
{
  "default": {
    "provider": "openai-generic",
    "model": "llama3.1:8b",
    "base_url": "http://localhost:11434/v1",
    "api_key_env": "OPENAI_API_KEY",
    "max_tokens": 1024
  }
}
```

```sh
WHIPPLESCRIPT_PROVIDER_PROFILES=./profiles.json OPENAI_API_KEY=ollama \
  whip run workflow.whip --provider owned --until idle
```

Whip drives the tool-use loop itself. Whip sends a tool as
`{type:"function", ...}`. Whip gives a result back as `role:"tool"`. Thus the
quality of the use of a tool follows the model. A small local model uses a tool
poorly. But the path on the wire is identical to the path of a hosted model that
is compatible with OpenAI.

> **On the host of a Durable Object**, an outbound call to a model must use
> HTTPS. The loopback interface is the exception. A hosted compatible endpoint
> such as OpenRouter or Together operates with no change. The host refuses a
> local endpoint that uses plain HTTP and that is not on the loopback interface.

## `whip auth`

Whip runs no login procedure of its own. Your environment already has
authentication from the `codex login` command and from the Claude CLI. A
coercion reads those credentials. Use the `whip auth` command to examine the
credentials that resolve, or to store an explicit API key:

```sh
whip auth status                           # show what resolves (redacted) + source
whip auth set anthropic sk-ant-api03-...   # store an explicit coerce credential
whip auth set openai     sk-proj-...
```

The `whip auth set` command writes a configuration file that only the owner can
read. The permissions are `0600`. The path is
`$WHIPPLESCRIPT_CONFIG_DIR/auth.json`. If you do not set that variable, the path
is in `$XDG_CONFIG_HOME/whipplescript/` or in `~/.config/whipplescript/`.

The precedence of a credential for a coercion is the **environment variable,
then the stored configuration, then the Codex OAuth token**. The OAuth token
applies to OpenAI only. Thus an environment variable always overrides a stored
key.

There are two different needs for a credential, but only one need is the job of
whip. A **coerce** statement and a **decide** statement use the credential that
the resolver above gives. A **harness** for an agent turn of Codex or of Claude
authenticates through the CLI of its own provider. The commands are
`codex login` and the `/login` command of the Claude CLI. Whip does not run
those procedures again. Whip uses the state that the environment already has.

## `whip mcp` — external MCP tool servers

The built-in harness can call tools that an external MCP server provides. Whip
is the MCP client. Whip executes each call itself, so each call passes the same
envelope as a built-in tool.

Register a server, then grant its tools per turn:

```sh
whip mcp add github --command npx \
  --arg -y --arg @modelcontextprotocol/server-github \
  --env GITHUB_PERSONAL_ACCESS_TOKEN=env:GH_PAT
whip mcp import ~/.claude.json     # or import the config you already have
whip mcp list
whip mcp status github             # connect and show the tools it offers
```

A value of the form `env:NAME` reads the environment variable `NAME` when whip
connects. The registry file holds the reference, not the secret. The path is
`$WHIPPLESCRIPT_MCP_CONFIG`, or `mcp.json` beside `auth.json`. The permissions
are `0600`.

### What whip can and cannot govern here

An MCP server holds its own credential. When whip calls `merge_pull_request`,
the merge happens under the token of the server, not under a token that whip
can narrow. **Adding an MCP server extends your trust boundary to the whole
authority of that server.** A per-turn grant reduces the blast radius. It is
not a claim about what the server is able to do.

Whip does enforce four things. It pins the manifest, so a server cannot rewrite
a tool description into new instructions for your model. It gives a stdio
server a cleaned environment, so the server does not inherit your API keys. It
admits each tool call against the grant, the pin, and the classification. It
records each call as evidence, and it records the trust level of each server
once per turn. It also marks the description of an unattested server as
untrusted content.

**One limit to know.** The static flow checker classifies a grant by the name of
the operation. The names it knows are `read`, `recall`, `get`, `list`, and
`import` for a read, and `write`, `learn`, `send`, `notify`, `emit`, `export`,
`append`, and `queue` for an egress. The operations in an MCP grant are the names
of tools, so the checker does not classify them. The checker therefore does not
report a flow from a confidential value into a tool argument. The same limit
applies to the `web { search fetch }` grant. For an MCP server the boundary that
the system does enforce is the governance envelope, which must govern the
`mcp:<server>` resource, together with the admission of each tool. Do not treat
the absence of a diagnostic as proof that no confidential value reached a server.

### The trust ladder

The ladder is progressive. The first rung needs no setup, and each rung above
it is a choice that an operator makes.

| Rung | How you reach it | What it buys |
| --- | --- | --- |
| `unattested` | `whip mcp add` | The server works. Grants name tools directly. Every call records an untrusted tag. |
| `pinned` | `whip mcp pin <name>` | Whip freezes the name, the schema, and the description of each tool. A later change fails the turn instead of passing quietly. |
| `attested` | `whip mcp attest <name> --trust-annotations` | The self-reported annotations of the server become usable classification. Role grants begin to resolve. |
| `classified` | A pin, plus a `roles` block in the registry file | You state which tools each role contains. This is the only rung that works for a server that publishes no annotations. A role file without a pin does not raise the rung: a classification of a manifest that can still change says nothing. |

Attestation is a real decision. The annotations of a server are its own claims.
The official MCP reference server marks a tool that returns every environment
variable as read-only and as non-destructive. Attest a server only when you
have read what it offers.

A `roles` block classifies the tools of a server:

```json
{ "servers": { "github": { "roles": {
    "read":  ["get_issue", "list_issues", "search_code"],
    "write": ["create_issue", "add_issue_comment"] } } } }
```

A program then grants `with access to github { read }`. A tool that no role
contains stays unavailable through a role. A new tool that the server adds
therefore never joins a role on its own.

### Drift

A pinned server that changes fails each turn that grants it. Review the change,
then accept it:

```sh
whip mcp sync github     # show the difference and re-pin
```

### Governance

An operator writes evidence with the commands above. A governance envelope
writes the requirement. The envelope holds a `require mcp <rung>` statement:

```text
require mcp attested
grant mcp github -> mcp:github readable by Ops
```

A server below the required rung exposes no tool. The requirement lives in the
signed envelope on purpose. If the requirement lived beside the evidence, the
person who attests a server could also lower the bar for it.

Whip refuses two parts of the MCP protocol. The `sampling` feature would let a
server run inference on the credentials of your workflow, outside the cost cap.
The `elicitation` feature would ask a person a question in the middle of a
turn. Use the tracker and the channels for a question to a person.

**MCP runs on the native path only in this release.** This applies to both
transports. The HTTP transport is the one that can reach the Durable Object
later, because one tool call has the same shape as one model call there. But no
MCP client runs in the isolate today, so a Durable Object turn that carries an
MCP grant is refused, not run without those tools. The `spec/durable-object-
runtime-tracker.md` file records the work that this needs. The stdio transport
needs a real process, so that transport stays native in any case.

## Effect kinds

| Effect | Created by | Executed as |
| --- | --- | --- |
| `agent.tell` | `tell` | an agent turn |
| `schema.coerce` | `coerce` / `decide` | a typed model decision |
| `tracker.file` / `tracker.claim` / `tracker.release` / `tracker.finish` | `file` / `claim` / `release` / `finish` | durable operations on the work tracker |
| `timer.wait` | `timer` | a delay that fires when the duration is due |
| `exec.command` | `exec` | a raw command in the dev profile, or a hosted script capability with a SHA-256 pin |
| `event.emit` | `emit <event> { ... }` | a typed event that the system injects into the stream of the facts of this instance |
| `signal.emit` | `emit signal` | the typed injection of a signal into a different instance |
| `lease.acquire` / `lease.release` | `acquire` / `release` | operations on a coordination lock or semaphore with the scope of the workspace |
| `ledger.append` | `append ... to <ledger>` | a durable write to an append log with partitions |
| `counter.consume` | `consume ... amount ...` | the consumption of a budget with a limit |
| `file.read` / `file.write` | `read text from <store> at <path>` / `write text to <store> at <path>` | a durable read or write through the path policy of a `file store` |
| `file.import` / `file.export` | `import <fmt> <Schema> from <store> ...` / `export <fmt> <Schema> to <store> ...` | structured records that the system reads from a path of a file store or writes to such a path |
| `workflow.invoke` | `invoke` | an instance of a child workflow |
| namespaced capabilities | `call package.capability` | a provider of a capability of a package |

## Packages

A package registers capabilities, providers, profiles, schemas, resources, and
optional skills. A first-class manifest of a package keeps the libraries, the
capabilities, the providers, the profiles, and the bindings separate. The
contract covers a package, a library, and a provider. A package exposes explicit
effects. A package never adds a hidden control flow and never adds a new
grammar.

```whip
use std.memory

rule fetch_context
  when WorkItem as item where item.status == "queued"
=> {
  call memory.query for item as context

  after context succeeds as found {
    tell worker as turn "Use this context: {{ found.summary }}"
  }
}
```

The `call` statement makes a durable `capability.call` effect, as each other
effect. The statement needs the capability of the package, which is
`memory.query` in the example. When the contract of a locked package declares
`validation: runtime_boundary`, the system checks the output of the provider
against the `output_schema` value. The system does this before it derives a
`capability.call.succeeded` fact. A mismatch fails the effect. A mismatch does
not become a fact of the workflow.

A package of the standard library, such as `std.memory`, is embedded in the
platform. A workflow needs only the `use` import. A package from a third party
needs a validation and a pin before use. A lock can never claim a `std.*` name,
because the embedded manifest always wins:

```sh
whip package check examples/packages/notes.json
whip package lock --output whip.lock examples/packages/notes.json
whip run workflow.whip --package-lock whip.lock
```

The packaging of a package is still experimental. Treat the manifest of a
package as part of the contract of the source that the system checks. Pin each
manifest with the `whip package lock` command. Commit the lockfile with the
workflow. Update the two files together.

## Practical advice

- Validate the orchestration with the fixture provider before you use a true
  provider. An assertion proves that the workflow gets to the intended state.
- Keep the identity of a provider in the metadata of the source. Use an
  `AgentRef<...>` value and the declarations of the agents. Never let the text
  output of a model select the route.
- When a true provider gives incorrect behavior, first read the `effects`, the
  `runs`, the `diagnostics`, and the `evidence`. Read the code of the adapter
  after that.
