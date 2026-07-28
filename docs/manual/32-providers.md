# Providers & harness configuration

Chapter 11 gave a rule that each subsequent chapter repeated: the component
that runs a turn is configuration and not code. This chapter gives the
configuration. A workflow makes three declarations: the `provider` family of an
agent, the provider of a coercion, and the provider of a channel. Each
declaration resolves here, outside the source. An operator owns each of these
items.

## The families of provider

- **`fixture`** — the deterministic replacement for development. This manual
  ran on the fixture. The fixture needs no credentials and no network. Its
  outputs are stable. Its terminal statuses are honest. A stub from chapter 25
  steers the fixture in each scenario.
- **`owned`** — the managed harness of whip. Whip drives the loop of the
  conversation itself. Whip brokers each call to a tool through the governed
  surface. Whip applies the profiles and the grants from chapter 11 *here*.
  Whip records the activity in a turn as evidence. During development, the
  fixture model supports this harness. In production, a true model supports
  this harness.
- **`codex` and `claude`** — the native integrations of a provider. These
  families give the loop of the turn to the agent runtime of the vendor. Whip
  observes the lifecycle and settles the effect. The credentials come from the
  configuration of the vendor. Codex uses the token in `~/.codex/auth.json` and
  the model in `~/.codex/config.toml`. Claude uses the API key of the Anthropic
  console. Whip runs no login procedure of its own. The `whip auth` command
  reports the credentials that whip can see.
- **`openai-generic`** — each endpoint that is compatible with OpenAI. A local
  model such as Ollama or vLLM binds through this family. An aggregator such as
  OpenRouter or Groq also binds through this family. The configuration is a
  base URL, a model name, and a reference to a key. This family is a *model
  backend*. This family is not a family of agent. A coercion selects this
  family directly. An agent gets to this family through the **owned** harness,
  which points at the endpoint. The declaration `provider openai-generic` is
  not valid for an agent.

The declaration of an agent gives the family. The compact form is
`provider <kind>`. The primary form in the reference is
`agent coder delegated to claude`, for an external runtime. The
`whip agents <workflow.whip>` command reports the bindings of a program. The
`whip providers <workflow.whip>` command reports the resolution of those
bindings. Sometimes a workflow needs more than one configured endpoint of one
family. In that condition, declare a named harness with `harness coder: codex`.
Then bind an agent with `agent worker using coder { … }`.

## Configuration files

A provider configuration is JSON that the operator supplies with the
`--provider-config <path>` flag. The configuration holds the endpoint for each
provider, the selection of the models, and the `prices` block. Chapter 29 uses
the `prices` block. The block gives a value in USD for each Mtok, for each
provider and model. Put a price on each item that you meter. If you do not, a
spend cap cannot bind.

Two rules make a configuration safe to commit. First, a credential is always a
*reference*. A reference is the name of an environment variable or an entry in
a keychain. A credential is never a literal value. Second, the configuration
selects among the declared families. The configuration cannot grant an agent a
capability or a profile that the source did not declare. The direction of the
authority never reverses. The source declares the ceiling. The configuration
selects the executor. Governance clears the principal. Chapter 24 gives
governance.

## The seam, from end to end

This is the sequence when a `tell implementer …` statement executes. The
sequence is the same for each family. The effect makes its request with the
profile and the grants of the agent. The worker resolves the family of the
agent through the provider configuration. The harness or the native runtime
then runs the turn under that authority. The owned family uses the harness. The
codex family and the claude family use the native runtime. The system records
the use of a tool in a turn as evidence. The owned harness brokers such use. A
native family reports such use. The settled outcome then derives the facts from
chapter 12.

Each family obeys the same contract. Thus this manual taught twenty chapters of
agent behavior on the fixture, and each part transfers. The *semantics* are in
whip. The family only changes the component that thinks.

A change of the family is correspondingly simple. That simplicity is the
feature:

```whip
agent implementer {
  provider codex
  profile "repo-writer"
  capacity 2
}
```

This declaration is the declaration from chapter 11 with one word changed. The
rules, the tests, the gauges, and the governance do not change. Under an
envelope for information flow, remember chapter 23. The *provider* is a
governed principal. Thus the change is also a question for governance. A
provider with no clearance is a denied egress, and the configuration cannot
change this result.

## A practical sequence for development

The examples in this manual suggest this path. Develop and test on the
`fixture` family. The fixture has no cost, is deterministic, and takes a stub
in each scenario. Do the first live runs on the owned harness that points at a
local `openai-generic` endpoint. This endpoint has no cost and is private, but
it is slow. Run production on the native family or on the owned harness that
your organization cleared. Configure the prices, and thus `std.spend` binds.
Each step changes one configuration file.

## Where next

Chapter 33 gives the tool with the most authority that an agent can hold. The
chapter gives script capabilities and the governed bash surface.
