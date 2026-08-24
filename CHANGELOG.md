# Changelog

All notable changes to WhippleScript are recorded here. This project aims to
follow [Semantic Versioning](https://semver.org). Dates are UTC.

## [0.5.6] — 2026-08-20

The labeled turn projection now publishes a turn's content as ordered
`segments` alongside the existing `assistant_text` and `tool_calls`.

`LabeledTurnOutput` is the only supported way for an embedding host to obtain a
turn's content, and it exposed only the *fold*: one final `assistant_text` plus
a flat list of the calls that ran. That fold answers "what did the turn
conclude", but it discards the order content was produced in, and every
intermediate line of prose the model spoke alongside a tool call — so a turn
that narrates its work projected as if it had said nothing until its closing
line. A shell that replays a turn as a conversation could not, and the contract
directs hosts not to recreate transcript-folding from the runtime store.

`TurnContentSegment` is `Prose(String)` or `Tool(ProjectedToolCall)`, and
`segments` carries them in the sequence the turn produced them — prose runs
interleaved with the calls they introduced, results correlated into position.
It is the same admitted content under the same turn-join label, so it carries
no read the folded fields do not already carry and does not widen the certified
`flow_signature`. Additive and compatible: `assistant_text` and `tool_calls`
are unchanged, so every existing consumer keeps its folded view.

## [0.5.5] — 2026-08-20

An agent turn's request dialect becomes a named, declared property of a
provider binding rather than something recovered by reading a base URL.
`ModelWire` — `anthropic-messages`, `openai-responses`, `openai-chat-compat`,
`coerced-tools` — is separate from `CoerceProvider`, which answers whose
credential pays; the two were one enum, and a metered gateway is a single
payer identity fronting three dialects.

The wire used to be recovered by testing an admitted base URL for an
`/anthropic` suffix, with everything else taking the chat-completions wire as
"the wire that has always worked". That default was wrong in production: an
OpenAI model whose family carries tools only on the Responses API was sent its
tools on chat completions and refused at the first turn that carried any,
while this runtime's Responses builder sat unreachable behind a mapping with
no arm that produced it. A binding may now declare its wire in the signed
policy, and the declaration travels through the turn admission to the host.
The surface mapping survives only as a fallback for envelopes signed before
the field existed: it is total, and an unrecognized surface is an error rather
than a guess.

`coerced-tools` is a new dialect and the floor beneath the model catalogue:
chat completions with `response_format` pinned to a `{reply, tool_calls[]}`
schema and no native tool array at all, so a model that can honour a JSON
schema can drive the loop whatever its endpoint implements. `DR-0064` records
it and states its cost — a tool request expressed as structured output is off
the format models are trained on — so native calling remains the default and
this remains a fallback. Brokering is unchanged: whip still executes every
tool the model requests, under the same lease, store policy, counter, and
capability gate.

Compatible with envelopes signed before this release. The `wire` field is
optional and omitted when absent, so an existing policy canonicalizes to the
bytes it was signed as and still verifies.

## [0.5.4] — 2026-08-19

xAI's Grok models become a first-class model backend, and the harness loop
exports its settled context-window reading — the number its own compaction
trigger consumes — so an embedding product can finally show an honest
context meter instead of a billing sum that overcounts the window by the
number of tool rounds. The endpoint already
worked through `openai-generic` plus a hand-set base URL, but that spelling
made the credential an "OpenAI key" and left the operator to know the URL;
a first-class `xai` backend owns its credential surface and its default.

### Added

- **`xai` model backend** — xAI's Grok API as a first-class backend on the
  model-backend axis (`spec/std-coercion.md` "Providers"): the Chat
  Completions wire at `https://api.x.ai/v1`, reachable everywhere the other
  backends are — native coerce (`WHIPPLESCRIPT_COERCE_PROVIDER=xai`), the
  owned agent harness (provider profiles and
  `WHIPPLESCRIPT_HARNESS_PROVIDER`), and the hosted Durable Object doors
  (`coerce_config_json` / agent config / model broker). The credential is
  `XAI_API_KEY` or `whip auth set xai` — its own surface, never the OpenAI
  one, and the Codex OAuth token never satisfies it. Grok context windows are
  derived per family (fast variants 2M, grok-4/grok-code 256k, conservative
  131k otherwise). Provider subprocess spawns (codex, claude) strip
  `XAI_API_KEY` the way they strip each other's keys.
- **`spec/std-coercion.md` "Adding a model backend"** — the exhaustive wiring
  checklist a new backend must cover, distilled from this addition and from
  the `openai-generic` reachability lesson.
- **Settled context-window reading** — `BrokeredTurnOutcome::last_input_tokens`
  (the final MAIN reply's prompt size), stamped once at the terminal into the
  usage object under `last_input_tokens` and projected by both hosts: the
  Durable Object's `usage_observation.last_input_tokens` and the local host's
  `TurnExecution::usage` (`TurnUsageObservation`). A gauge beside the meter:
  billing settlement deliberately keeps carrying only the four summed
  counters.

## [0.5.3] — 2026-08-17

The authored half of durable-store upgrades (compiler half: 0.5.2). An
embedding host whose package assembly evolved resolves different authored
content under the reference an older build recorded; the replayed open
refuses — correctly, and permanently, stranding the instance's thread.

### Added

- `GovernedHostRuntime::adopt_instance_from` — a fork that waives only
  source-content reproduction: identity, policy binding, position, and
  quiescence are checked exactly as an ordinary fork; the source is never
  executed again; its thread seeds a target resolved in full under the
  current authoring; `host.instance.forked` audits the move.
- `GovernedHostRuntime::newest_recorded_instance` — names the adoption
  source for a host that cannot replay an open to find it.

## [0.5.2] — 2026-08-17

Durable stores survive toolchain upgrades. Consuming 0.5.1 from GaugeDesk
surfaced that the replayed-open guard stranded every pre-existing instance
after a compiler-evolving upgrade: the recorded `ir_hash` could never match
what the new toolchain derives for the identical authored program.

### Fixed

- **A replayed instance open re-attests the IR under the current compiler**
  when the authored identity (`source_hash`) matches and only the compiled
  identity (`ir_hash`) differs. The current compile is registered as a program
  version, the instance is re-pointed, and `instance.program.reattested` is
  appended naming both IRs — an auditable event, never a silent acceptance.
  A differing `source_hash` stays refused: different authored content under a
  replayed request is the integrity breach the guard exists for
  (`spec/agent-harness.md` "Program identity across toolchains").

### Added

- `RuntimeStore::reattest_instance_program`, implemented for the native
  `SqliteStore` and the durable-object `DoSqliteStore`.

## [0.5.1] — 2026-08-17

Stop lands mid-stream. Cancellation of a brokered turn was cooperative only
between model rounds, so a Stop aimed at a long single-response turn waited for
the entire response to stream — indistinguishable, from an embedding UI, from
the Stop doing nothing.

### Fixed

- **The native transport releases a cancelled turn's provider stream** instead
  of draining it. The transport polls the durable cancellation surface between
  streamed SSE lines (its own throttled store connection, latching on first
  observation) and releases the stream at a complete-line boundary; what fully
  arrived assembles exactly as a naturally ended body.
- **A released round settles `cancelled`, keeping the text that arrived** as
  that round's durable assistant message, and starts no offered tool — a
  truncated text tail parses exactly like a final answer, and settling it
  `completed` would launder a stop into a normal terminal. An unreleased
  natural terminal still wins over a racing request, and transports without a
  release surface keep the between-rounds observation unchanged
  (`spec/agent-harness.md` "Cancellation").

### Added

- `BrokeredTurnMachine::with_stream_released` and the
  `BrokeredTurnContext::stream_released` probe, for hosts whose transports can
  release an in-flight stream. `None` preserves prior behavior exactly.

## [0.5.0] — 2026-08-17

Multi-party governance. A run stops being governed by one envelope and starts
being governed by a **set** of them, whose effective policy is their meet
(DR-0063). The single-authority posture is unchanged and unqualified: one
envelope naming no authority behaves exactly as it did.

### Breaking

- **The governance signing preimage gains the epoch and the authority**, under a
  new domain tag (`whipplescript-governance-envelope:v2`). Under `:v1` the same
  valid signature verified under whatever epoch the caller named, so a
  constituent could be presented as a different — including an earlier — policy
  revision. That is precisely the non-retroactivity claim a composition record is
  meant to carry, so the epoch had to move inside the signature rather than
  beside it. `:v1` stays verifiable for the single-envelope path and is
  **inadmissible in a composed set**.

  A half-stated `:v2` — epoch present without authority, or the reverse — is
  refused rather than silently downgraded, because that is how an epoch would
  come to look signed without being.

- **The hosted path is `:v2`-only.** `verify_epoch(epoch, signed)` became
  `verify(signed)` and reads the epoch from the attestation, so every `host_*`
  export dropped its `epoch: u64` parameter and the Worker moved with it. A
  `:v1`-signed envelope is refused there and must be re-signed. The caller no
  longer gets to say which policy revision it is holding.

- **A role is qualified by the authority whose envelope declares it.** `acme::
  Operator` and `beta::Operator` are different principals, and a composition can
  never unify them by name. An envelope that names no authority keeps bare roles
  and is unaffected.

### Added

- **Envelope composition** (DR-0063): `Composition::compose` checks a set of
  signed envelopes as their meet, defined by refusal — the composed policy
  refuses whenever any constituent would. Every per-arm rule follows from one
  question: at a crossing the kernel asks `dominates(provider, required)`, so the
  `required` side composes by union and the `provider` side by intersection.
  Confidentiality puts the sink on the provider side and integrity puts the
  source there, which is why the two compose in opposite directions rather than
  by two rules kept in step.

  Composition fails closed on any ill-formedness rather than dropping the
  offending arm, because a silently dropped grant is one its issuer goes on
  believing it holds.

- **`requires authority <id>`** — an envelope's grants are valid only inside a
  composition that includes that authority, present *and governed*. This is how
  one party's policy depends on another's constraints actually holding, rather
  than on the other party merely being named somewhere.

- **A composition record**, `(authority, envelope_hash, epoch)` per constituent:
  what the run was actually checked under, and what its evidence and guarantee
  report cite.

- **Dual labels.** A resource's confidentiality and integrity readings may
  differ, so a handle is no longer forced to carry one label for both axes.

- **`exposes`** — a counterparty may narrow a resource it does not own,
  referencing it by an opaque id rather than an address. Minting stays with the
  owner; a second authority can only reference a key, never mint one.

- **`policy lifetime`** — how long a pinned composition may be relied on without
  re-admitting under a freshly composed set. Unbounded is the single-authority
  posture; without a bound an unbounded `@service` loop holds its composed set
  forever and "non-retroactive" quietly becomes "never".

- **`CompositionProjection`** — what one authority may see of a composed set.
  Presence is not disclosure: the projection names every authority but only the
  viewer's own governed resources.

### Fixed

- **Canonicalization is proven lossless rather than assumed.** `gov::canonicalize`
  round-trips an envelope through its canonical JSON, so any field the emitter did
  not write was dropped from the *signed* document — it parsed, then vanished at
  signing, and its check passed vacuously. This cost four fields before it was
  closed structurally: `authority`, `requires_authority`, `exposes`/`attachments`,
  and `policy_lifetime`.

  The repair is a total property asserted inside `canonicalize` — reparsing the
  canonical form must reproduce the envelope — rather than another per-field
  test. Envelopes now normalize at *parse* instead of at emit, which is what makes
  the comparison exact. A new arm needs no test edit: omitting it from the emitter
  fails everywhere at once.

- **A glob resource address is refused rather than accepted and ignored.**
  `information-flow-surface.md` promised `file:/data/**` with most-specific-wins;
  the checker only ever matched exactly, so a policy author could write a pattern
  that governed nothing and read as though it governed everything. Globs were
  retracted from the spec rather than implemented, and the address surface now
  refuses a pattern at declaration — the route out of a refusal being the whole
  value of it.

- Contract-registry identifiers are held to being non-empty.

- **Scratch paths are unique per call, not per `(pid, label)`.** Three helpers —
  the verified-artifact bundle writer, the artifact-bridge platform catalog, and
  the Maude runner — derived a temp path from the pid and a hash of a
  caller-supplied label. One process running two of them at once for the same
  label derived *one* path, and whichever finished first deleted the file the
  other was still reading. It had already bitten: splitting the CLI test module
  changed scheduling enough that two tests naming the same source began to
  overlap and the bridge failed about one run in four.

### Documented

- The release checklist no longer tells the next cut to publish the private tree.
  The mirror is not a git mirror — its history is a disjoint sequence of squashed
  snapshots — so a tag made on a `-src` commit and pushed to the mirror publishes
  that object, `spec/` and all.
- The Homebrew tap is documented as existing, because it does.
- Witnesses added for which bytes a composed label is about, the governance
  envelope's refusals, the declaration surface's refusals including the
  half-written ones, and the type checker's operand and record-construction rules.

## [0.4.1] — 2026-07-29

### Fixed
- **An endorsed claim now prints in the guarantee report's trusted surface**
  (DR-0051 §2). It never had. The surface is built by walking a rule's effects
  for the `endorsed` flag, and a `claim` is not an effect, so the crossing 0.4.0
  introduced was invisible to the audit surface that same release documented it
  in.

  The consequence landed where it mattered most: a program whose only crossing is
  a person's adopted decision — a human review gate — rendered a report with no
  source crossing on it at all, which reads as "this program raises nothing"
  about the one program whose whole job is to raise something.

  The line names the tracker as well as the rule, so `endorse <tracker> ->
  <role>` on the governance side and the source crossing can be matched up as the
  two ends of one crossing.

### Documented
- DR-0051 §4's closed-type predicate binds `claim … endorsed` and **not**
  `coerce … endorsed`, and the record now says why. Not because a classifier is
  more trustworthy than a reviewer — it is less — but because a reviewer is
  handed a free-text box and cannot be told to sanitise it, while a coerce
  endorser is a program with a declared schema whose canonical documented use
  (`sanitize(content) -> Note { note string }`) is producing trusted prose. The
  residual is named rather than waved off.
- `ifc.rs`'s module header no longer claims the source crossings "arrive in later
  slices"; they shipped several releases ago.

## [0.4.0] — 2026-07-29

Information-flow work: trackers become governed resources, and a person's
decision can cross the integrity axis for the first time.

### Breaking
- **A tracker is an information-flow source** (DR-0051 §1). A `when <tracker> has
  ready issue as v` trigger now reads a governed resource, labelled by
  `grant tracker <handle> -> tracker:/<address> from <Role>` and defaulting to
  `public` when ungranted.

  This closes a hole rather than adding a restriction. Before it, issue text
  reached a `from`-labelled sink with no grant and no diagnostic — and *still*
  did when the tracker was explicitly labelled `from public`, because the label
  was never consulted. A tracker is an inbound channel with a durable queue and
  an external filing surface, which is exactly what I-IFC is about.

  **Migration:** a whip reading a tracker into a `from`-labelled sink needs one
  line naming who may file into that queue. A whip reading a tracker into
  unlabelled sinks is unaffected — `public` into `public` was always fine.

### Added
- **`claim … endorsed`** (DR-0051 §2), the integrity crossing for a party's
  decision, marked and audited exactly as `coerce … endorsed` is. The crossed
  value is the claimed *item*, not the claim's `as` binding: `claim v as hold`
  binds a lease in `hold` while the decision the program reads lives in `v`.

  Honoured **only when the claimed tracker is vouched** (§3). Without that the
  marker would be a hole rather than a crossing — an agent can file an issue, so
  it could file its own verdict and claim it, laundering its own output through a
  two-step it fully controls.
- **Endorsed decisions must be bounded** (§4). A record field shaped by an
  endorsed claim must carry a value that cannot express prose: a closed union of
  string literals, or a non-string primitive. A bare `string`, a map, or a union
  with one bare arm (`"keep" | string`, which is reopened) is refused. Numbers
  are admitted deliberately — an `int` cannot instruct a downstream reader.

  This binds a *fully honest* endorser, not a compromised one. A reviewer who
  quotes a hostile item into a free-text verdict has done their job and has also
  relayed attacker text into a fact labelled as vouched.

  It does not touch the payload under review. A gate is a valve, not a filter:
  this governs the control signal, never what flows through.

### Notes
- DR-0051 §5 (an attacker must not steer *which* reviewer is asked) is specified
  but vacuous today and implemented as nothing: the whip surface has no assignee
  to steer. `assigned_to` exists only in `whipplescript-store`, as a durable
  column with no language-visible field.
- Entries for `0.2.2`, `0.2.3`, `0.3.0`, and `0.3.1` were never written. Those
  releases are recorded in their decision records — notably
  DR-0050 for the `ask_human`
  removal cut as `0.3.1`. This gap is noted rather than backfilled.

## [0.2.1] — 2026-07-27

The first feature release since `0.1.1`, and a large one: a new MCP client
subsystem, four breaking language/runtime changes, the information-flow work of
DR-0044/0045/0046, pinned progressions, a public Session durable-object runtime,
and a complete 35-chapter manual.

**Why 0.2.1 and not 0.2.0:** this is the v0.2 milestone, but a `v0.2.0` tag was
already published on 2026-07-06 under the abandoned 0.2/0.3/0.4 version ladder
that was later collapsed into a single `v0.1.0`. That number is spent, and
rewriting a pushed tag is not worth the tidier arithmetic, so the release takes
the next free number in the 0.2 line. `0.3.0` was not an option either: an early
`whipplescript-core 0.3.0` is published on crates.io from the same abandoned
ladder.

Read the third component as "next free", not as "patch": coming from `0.1.1`
this is a minor step, and it carries the breaking changes listed below. If you
are somehow on the old `v0.2.0` tag, this is not a safe patch upgrade — that tag
predates the whole collapsed line.

### Breaking
- **File stores are read-only by default.** Reads need no clause, but writes and
  exports are denied unless the store declares `allow write [...]`. This closes a
  fail-open: `allow read ["**"]` *looked* read-only while writes were
  unrestricted. Enforced at compile time and again at runtime.
- **`askHuman` is gone from the language.** The action, the `when human answered`
  readiness, the `HumanAnswer` schema, the `choices` clause, and the underlying
  effect kind are removed from parser, IR, IFC, kernel, CLI, examples, and docs.
  Human review now goes through the tracker (`file issue into <queue>` → `whip
  issue` → a rule reacts to the finish) and channels.
- **The owned harness has no `ask_human` tool.** The tool, the turn-suspend
  mechanism, the inbox store and its API, the `whip inbox` command, the
  `human-review` profile, and the `human.ask` capability are all removed.
  **Note the scope:** this removed the *owned harness's* human gate. The public
  Session durable-object runtime added in this same release carries its own
  human-answer path, so a durable turn can still park as `AwaitingHuman` and be
  resumed by an admitted answer through that runtime.
- **Identity hashes are re-keyed from FNV-1a 64-bit to SHA-256/128** everywhere
  user content reaches a key. Stores written before this change cannot be read by
  this version — retire them.
- **Agent package manifests must declare `agent_abilities` explicitly.** The
  ability ceiling is no longer inferred from `capabilities`.
- **`succeeds` arms are rejected on variant-valued coordination bindings**, where
  they were previously accepted and meaningless.
- **The `flow` construct is deleted.** Sequential composition is now the `then`
  continuation sugar. A program using `flow` no longer compiles. (Removing it
  fixed two latent kernel bugs on the way.)
- **`use std.<pkg>` is now required** to reach a standard package's constructs
  (the DQ-1 authority split). A program that relied on ambient availability must
  add the import.
- **The CLI verbs moved, and `run` changed meaning.** `dev` was renamed to `run`,
  and the old `run` became `start`. There are no aliases. This is the dangerous
  shape of a rename: `run` still exists and still works, but it now runs locally
  to idle instead of starting a durable instance and returning. A script that
  called `run` expecting the old behaviour will keep working and do the wrong
  thing. Rewrite `run` to `start`, and `dev` to `run`.

### Added
- **MCP client support for the built-in harness.** A turn can draw tools from
  external MCP servers, brokered by whip so every call crosses the same envelope
  as a native tool. Governed by a four-rung progressive-rigor trust ladder:
  `unattested` works with zero setup and tags every call, `pinned` freezes the
  tool manifest (name, schema, and description) so a server cannot silently
  rewrite a description into instructions for your model, `attested` admits the
  server's self-reported annotations as classification, and `classified` uses an
  operator-written role file. Grants enumerate tool names; tools are namespaced
  `mcp__<server>__<tool>` so a server shipping `read`/`write` cannot shadow the
  governed file tools. Arguments are treated as egress and results and
  descriptions as low-integrity ingress. Stdio servers are launched with a
  cleaned environment rather than inheriting whip's. The `sampling` and
  `elicitation` sub-protocols are refused. New commands: `whip mcp
  add|import|list|status|pin|sync|attest|forget`, including `whip mcp import` for
  an existing Claude Code or Cursor `mcpServers` block.
- **A governance envelope can require a minimum MCP trust rung** with `require
  mcp <rung>`. The requirement lives in the signed envelope while the evidence
  (pin, attestation, roles) lives in the operator registry, so whoever attests a
  server cannot also lower the bar it is judged against.
- **Pinned progressions (DR-0043)**: firing records embed their pinned context,
  `during`/`until` regions with `on lapse` arms, old-body completion under
  revision, plus `whip progressions` and `whip progression cancel`.
- **Cross-rule fact provenance (DR-0045)** and **effect-output integrity
  (DR-0046)**: executor and model outputs are governed writers, and the label
  token is origin-aware.
- **A public, session-owned durable-object runtime (DR-0047)**: resumable session
  protocol, transcripts persisted in the object, audience-bound turns, retention
  alarms that destroy session authority, and provider secrets resolved only at
  final fetch.
- **The manual** — 35 chapters across five parts, plus a tutorials series and
  audience-routed site copy. The documentation set is written in ASD-STE100
  Simplified Technical English.
- **Dual MIT/Apache-2.0 licensing** and a contribution policy.
- `whip run --wait`, full-line comments inside rule bodies, `finish ... as
  <binding>`, and defaults for agent declarations so a bare `agent <name>` is
  complete.

### Changed
- **Information-flow control is stated as deny-properties.** All 11 IFC checker
  diagnostics now lead with the denial — naming the victim and the forbidden
  audience first, with the universal rule it instances in parentheses and the
  repair unchanged. The mechanism is unchanged; the framing and the docs are not.
- Rule-level auto-fail for unhandled effect failures, with a prominent check
  warning; per-kind typed failure extras behind static narrowing.
- Grants authorize marked crossings only, enforcing DR-0027 I-IFC3, with
  input-side provenance narrowing.

### Fixed
- Hang-class kernel bugs: scanner tail-loss, string-blind brace matching, dropped
  cancels, and factless terminals.
- `after x times out` arms never fired — `fails` was wrongly catching timeouts.
  Fixture timeout and cancel stubs now emit real terminals.
- Payload-scope evaluation, fact re-recording collapsing instead of crashing the
  step, and observation of cancelled effects.
- Crash windows closed: replay-tolerant `derive_fact`, terminal-retry healing, and
  projection revive.
- `record <T> from <b>` now actually copies the source fields.
- Cross-clone lease destruction, and lease identity is now the acquire event's
  content id.
- Durable-object host parity: event idempotency index, commit replay guard, real
  cancelled terminals, and honest unsupported-effect reporting.

### Deferred
- **MCP on the durable object.** The native path shipped; the isolate path did
  not, because `ToolExecutor::execute` is synchronous and so no network-reaching
  tool can run there — the same gap that has kept `web_search` and `web_fetch`
  off the durable object. The shared suspension seam is specified as the first
  open item on the durable-object tracker. In the meantime a durable-object turn
  that carries an MCP grant is **refused** rather than run without those tools.

## [0.1.1] — 2026-07-20

A correctness patch for the generic OpenAI-compatible provider path and spend
accounting, from live validation against a real local endpoint (Ollama).

### Fixed
- `openai-generic` default base URL now carries the `/v1` segment the Chat
  Completions builder expects; relying on the default (or pointing at
  api.openai.com without a hand-added `/v1`) previously 404'd.
- The owned-harness provider-profile parser and `WHIPPLESCRIPT_HARNESS_PROVIDER`
  now accept `openai-generic` — the agent-turn path for OpenAI-compatible
  endpoints (Ollama, vLLM, OpenRouter, …) was implemented but unreachable
  through configuration.
- OpenAI-chat-shaped usage (`prompt_tokens` / `completion_tokens`) is now
  priced; it previously parsed as zero tokens and recorded as unpriced.
- Anthropic prompt-cache traffic (`cache_read_input_tokens` /
  `cache_creation_input_tokens`) now counts toward `std.tokens` and prices into
  spend; it was previously invisible ($0) to the spend cap.
- A campaign that spends under a `--spend-cap` while any usage is unpriced now
  ends with an operator warning and a `campaign.spend_cap_unpriced` record
  event instead of letting the cap silently under-count.

### Added
- Provider usage is normalized into disjoint uncached / cache-read /
  cache-write buckets by wire shape (Anthropic-style and OpenAI-style usage
  objects both supported, including future engines that mimic either).
- Optional `cache_read_per_mtok_usd` / `cache_write_per_mtok_usd` price-table
  rates; absent rates price cache traffic at the input rate (a conservative
  overestimate, so an underspecified table can only over-count toward a cap).
- New builtin gauge `std.cache_hit` (ascending): provider prompt-cache hit
  rate, present only when the provider reports cache usage.
- docs: "OpenAI-compatible & local models" guide (coerce + agent-turn recipes,
  the `/v1` base-URL convention, DO HTTPS-except-loopback caveat) and expanded
  spend-price documentation.

## [0.1.0] — 2026-07-17

The first public release of WhippleScript — a small scripting language for AI to
orchestrate AI, built on a durable, replayable rule/effect kernel with a
scriptable surface. Safe to run by default; explicit, gated escape hatches for
external scripts and agents; LLM-driven control flow goes through coerce-typed
decisions. This release is the complete language, its standard library, native
and cloud runtimes, the owned agent harness, and WhippleScript's own version
control — documented, tested, and formally modeled.

### The language
- Explicit `workflow` declarations with typed `input` / `output` / `failure`
  contracts (and a compact single-line signature form); `include` source
  bundles, `use` package imports, non-recursive `pattern` / `apply` reuse, and
  durable child `invoke` with typed success/failure/timeout/cancellation.
- `flow` — a sequential surface that lowers to rules, with per-step `on fails` /
  `on timeout` handlers and branch-liveness checks.
- A shared, typed expression kernel for guards and assertions: boolean logic,
  ordering, membership, `exists` / `empty` / `count`, optional presence proofs,
  finite-domain (enum / literal-union) checking, and fact/effect projection
  queries — with static diagnostics and generated per-program Maude checks.
- `case` pattern matching over enums, literal unions, optionals, tagged terminal
  outputs, and data-carrying sum-type variants, with exhaustiveness checking.

### Effects
- Agent turns (`tell`) with typed `AgentRef` routing and declared
  capability/profile/capacity enforcement.
- Schema coercion — named `coerce ... -> Type`, inline `decide`, and a bare
  `prompt "..." -> text` free-text effect.
- Deterministic JSON/JSONL ingestion via `exec ... -> Type` / `-> each Type`.
- Capability-gated `exec` (operator allowlist) and content-pinned hosted
  `exec <name> with <record> -> Type` (`std.script`, hard-off without the import).
- Time: `timeout` on any effect, relative and absolute (`timer until`) timers,
  and source-level `cancel`.

### Standard library
Thirteen standard packages, each documented and store/TLA/Maude-tested; they
resolve via signed lockfiles or embedded manifests (a `use`d standard package
works with no lock), a platform capability catalogue, and reserved-word
privileges — no ambient authority.
- **std.coord** — `lease` (incl. N-slot), `ledger`, `counter`; bounded
  `acquire ... wait`, `renew`, at-most-one-lease + lease-order deadlock safety,
  TLA-proven store protocols.
- **std.tracker** — a durable, merge-friendly work tracker (see below).
- **std.messaging** — `channel` + outbound `send` (local mailbox / stdio) and
  inbound `Message` receive.
- **std.ingress** — typed `signal` admission and `source` observers (clock with
  recurrence, file, HTTP), plus `whip signal`.
- **std.memory** — named pools with `learn` / `recall` / `curate` and
  turn-scoped grants, over a real file provider (native and DO planes).
- **std.time** — timers, deadlines, `time` values, the `clock` source.
- **std.files** — `read` / `write` / `import` / `export` with path policy and
  turn-scoped grants.
- **std.telemetry** — cursor-tracked OTLP export (`whip otel-export`),
  structural-by-default, failure-isolated, replay-safe.
- **std.coercion** — the schema-coercion backend contract (native structured
  outputs).
- **std.script** — content-pinned hosted `exec` capabilities.
- **std.agent** / **std.web** — agent-turn and web-tool surfaces.

### Distributed work tracker (std.tracker phase B)
- The tracker's log is a content-addressed **Merkle event DAG** (SHA-256):
  every event is content-hashed over its kind/issue/payload/actor/parents, and
  an issue's identity is the hash of its creation event — tamper-evident and
  merge-stable, with `WS-N` kept as a durable clone-local alias.
- Multi-writer merge is a set-union of the content-addressed log deduped by
  event id; a **per-field conflict engine** surfaces disagreeing concurrent
  edits (a conflicted issue is not ready), resolved by a plain `set`. Optimistic
  concurrency via `--expect-state-token`.
- A full relation taxonomy (blocks / parent-of / related / duplicates /
  supersedes / discovered-from; only `blocks` gates readiness), comments, and
  evidence — each merge-stable.
- Cross-machine transport: the log serializes as content-addressed files, so two
  clones reconcile to a byte-identical frontier by sharing a folder (`whip issue
  export` / `import` / `sync`). The durable-object backend mints identical ids,
  so a DO log and a native log interoperate. Genuine duplicate submissions are
  surfaced; idempotent re-sync stays quiet.

### Native runtime & providers
- Durable SQLite runtime with event-sourced replay, workflow revision, and a
  `worker` / `dev` driver; deterministic fixtures for CI.
- Native **Codex** (app-server) and **Claude** (Agent SDK sidecar) providers,
  live-validated: lifecycle normalization to `agent.turn.*`, provider-native
  cancellation, artifact/evidence capture with redaction, crash/restart
  recovery. Providers are separable crates behind an open, string-keyed registry.

### Cloud runtime — Cloudflare Durable Object
- A sans-IO core (parser, kernel, rule/flow engine, effect ledger) runs inside a
  single-threaded wasm isolate where the only async primitive is `fetch`: every
  HTTP-bearing effect is a resumable step machine that suspends on a request and
  resumes on the response, surviving isolate eviction with no lost work.
- DO host binding over synchronous SQLite (a full port of the runtime /
  coordination / work-item / tracker stores), alarms for timers, secrets for
  credentials. `whip deploy` is a one-command edge deploy.
- Feature parity with native: `file.*` over a DO-owned file plane; `whip
  checkpoint` / `restore` as operator commands on a deployed instance; a real
  in-isolate tool set (read/write/edit/ls/find/grep/recall + tracker todos)
  against DO storage — no filesystem, no subprocess.
- A Class-A compute plane (`whip executor` sidecar over `whip-executor/1`, Bearer
  auth, loopback-only) and a Class-B per-turn container path are built and
  live-proven; production enablement is a follow-on configuration step.

### Owned agent harness
- A context layer: system-prompt assembler, a skills control plane (discover-all
  + model-driven read; skill bodies content-addressed; skills never grant
  authority), deploy-shipped project instructions (`AGENTS.md` / `CLAUDE.md`,
  injected verbatim), and turn-scoped skill pins.
- The `bash` tool runs in an in-isolate virtual shell (Bashkit) over the governed
  workspace VFS — no fork/exec, ambient filesystem, or ambient network — on both
  native and DO.
- Cache-aware conversation compaction: a pluggable `Compactor` (three strategies)
  keeps the assembled prefix append-only between compactions so the provider
  prompt cache is not needlessly busted; the summary is recorded once and reused
  on replay.

### Version control — the versioned workspace
WhippleScript gains its own version control: workspace-as-database with O(1)
branches over a content-addressed store, where an instance's files,
conversation, and effects move as one coherent, provenance-carrying line.
- Branches, cuts, and virtual working sets: O(1) branches, per-instance
  copy-on-write file surfaces, branch-distinct effect keys, materialize-on-exec.
- The mapped 13-operation workspace API (refusals as data), the op log as a
  first-class reflog with `whip branch undo-op`, review-grade Myers diffs,
  handoff bundles (`whipplescript.bundle.v1`) with chunk-granular delta transfer,
  and per-blob erasure discharging `HISTORY_PRESERVED` /
  `EXPORTED_COPY_NOT_RECALLED` by test.
- Selection algebra (`path()` / `by-effect()` / `since()` / `dependents-of()`
  with `| ~ &`) behind selective `undo` / `transport` / `adopt --only` — dry-run
  by default, stranding-checked, no destructive verbs.
- Structured conflicts with rerere-style resolution memory an auto-propagating
  reconciliation daemon; checkout-free `bisect`, `attribution`, `log`; and `whip
  fork` — the chat fork, seeding a new instance from a source's completed turns.

### Experimentation & improve
- `gauge` + `mark` (pin / suppose / settle / evidence / why) for ambient
  experimentation; identification-first quasi-experimental posture; an
  evidence-plane IFC (scope ⊥ clearance); `campaign` declarations; and the
  `improve` loop (holdout-validated, priced spend/park/resume, estimator +
  reopener) over parallel evaluation.

### Web & network access
- `web_search` (SearchProvider trait; Brave first-party, model-provider floor,
  honest absent tier) and `web_fetch` (structurally GET-only behind a central
  SSRF guard with pinned connections and redirect re-entry; HTML→markdown),
  granted via `with access to web { search fetch }`.
- `http source` fetches an external URL GET-only behind an SSRF/egress policy
  (http(s) only, private/loopback blocked, host allowlist).

### Policy plane, IFC, and the store seam
- Static information-flow control: session-root scoping, per-field producer-side
  flow signatures, `redact ... keep [...]`, typed effect failures (`fails as f`),
  and a hermetic Lean proof layer.
- Signed governance envelopes: hosts require an envelope, verify its attestation,
  and bind a policy epoch to the verified canonical hash and signer; a malformed
  envelope fails closed. `whipplescript.host.v1` publishes policy-bound turn
  commands, labeled evidence references, stable event positions, and terminal
  receipts (mixup-rejecting; resources/providers stay references, not copies).
- DR-0036 turn receipts carry a witnessed workspace cut (`workspace_cut_ref`,
  honest-decline when a segment is unwitnessed) and a dynamic guarantee section
  (`writes_within:<scope>` / `no_reads_beyond_grant` / `no_tainted_reads:<class>`)
  evaluated per turn under the cited policy epoch.
- Host-resolved provider profiles (`WHIPPLESCRIPT_PROVIDER_PROFILES`): the policy
  channel hands whip resolved credentials; whip's own auth is the thin fallback.
- The store seam: `whip handles` (stable pointers for external admission logs)
  and `whip checkpoint --external-positions` (position-pair cut for cross-store
  backup/handoff).

### Restorable context
- `whip checkpoint` / `restore`: rewind an agent's files, transcript, and
  event-log position to a prior point as one coherence-checked cut — content-
  addressed, refuses a partial cut, and auto-checkpoints head so the undo is
  itself undoable.

### Reliability
- Every provider request carries a stable per-effect `Idempotency-Key`
  (resume-stable), so an at-least-once retry after an eviction mid-request is
  de-duplicated by providers that honor it.

### Tooling
- `whip check` / `dev` / `worker` / `run` / `status` / `diagnostics` / `doctor`,
  `whip lint` (zero-false-positive analyses), `whip lsp`, `whip fmt`, and the
  `agents` / `providers` / `skills` introspection commands.

### Formal models & distribution
- A gate-registered Maude + TLA+ model suite (rule system, flow, coordination
  protocols, merge/conflict, workspace ops, turn witness, tracker readiness, …)
  with verified bites, plus per-program generated model checks.
- `cargo install` source path and cargo-dist release artifacts for macOS / Linux
  / Windows with shell and PowerShell installers and checksums.
