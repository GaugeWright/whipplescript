# Changelog

All notable changes to WhippleScript are recorded here. This project aims to
follow [Semantic Versioning](https://semver.org). Dates are UTC.

## [Unreleased]

### Added

- **`mint credential from <parent> { … }`** (DR-0053 §5, as amended
  2026-08-27) — spend a credential at an issuer's token endpoint for a scoped
  child. The exchange is the author's, in the block form `request` established;
  the custodian executes it so the minted token never enters whip. Three
  refusals: an undeclared parent, an exchange presenting nothing, and an
  exchange presenting a different credential than the one minted from.

- **A minted credential can never reach further than the credential it was
  minted from** (DR-0053 §5, as amended 2026-08-27).

  The custodian registers a mint as `{parent}/mint-{fingerprint}` and credential
  names are `/`-separated, so the egress ceiling now walks up the name. Nearest
  ancestor wins, so governance can narrow one mint further by naming it without
  restating the parent's list — and a governed-but-unscoped parent bounds its
  mints at nothing, rather than letting a child be the way around the ceiling.

  This is what `mint` is bounded by instead of a declared scope. `scope` and
  `ttl` are gone from `CustodyOp::Mint`: both were accepted and ignored
  (`_scope`, `let _ = ttl_secs`), both are vendor protocol, and both belong in
  the exchange body that actually goes on the wire. A clause beside the body
  duplicating it is the separate modifier §5 refuses for credentials — and the
  divergence was unresolvable, since §3 keeps the custodian from parsing the
  body, so a declared scope could never be checked against the exchanged one.

  whip therefore does not police which scope a mint *requests* — that string's
  meaning lives inside the vendor — and keeps the guarantee it can verify.

- **A credential's egress reach is bounded by governance** (DR-0053 §14, as
  amended 2026-08-27).

  ```text
  grant credential stripe_api -> credential:acme/stripe-live sealed at hardware
  grant request    stripe_api for POST https://api.stripe.com/v1/refunds/*
  ```

  §14 grounded scope narrowing in the *turn* grant, which attaches only to
  `tell` and `invoke`. The rule-body `request` — the one construct that reaches
  the custodian — had no list to consult, and an agent had no custody surface,
  so the turn clause parsed, passed its class check, and bound nothing.

  The ceiling now lives in the signed envelope, where it binds regardless of
  which construct uses the credential and no program text can widen it. It is
  in the canonical form, so the signature covers it. Refused at check time for
  a literal URL and at egress always. It applies once governance *binds* the
  credential; a policy that never mentions one does not constrain it.

  Matching is component-wise against a parsed URL: `*` never crosses from host
  into path, and userinfo cannot impersonate a host. A leading `*` must stand
  for a whole label — `*.stripe.com` is the subdomain wildcard, `*stripe.com`
  is refused because it reads as narrowed while admitting `evil-stripe.com`.

- **Agents can make authenticated requests, narrowed by their turn grant.** A
  `credential_request` tool is offered only to a turn whose grant lists
  `request` on a credential, and enumerates exactly those credentials. A call
  is admitted only when the turn's globs *and* the envelope's scope both admit
  it — a turn narrows, never widens, the same way a file-store turn grant sits
  under the store's own `allow` globs. The material never enters the agent's
  process: the turn names a credential and the custodian substitutes at egress.

### Changed

- **A source span is no longer part of a program's identity** (DR-0095).
  `ir_hash` is now `stable_hash_hex` of the `.ir` snapshot's *identity
  projection* — the same document with its source offsets erased. So **a
  compiler change that only improves a diagnostic span rotates nothing**, and
  `ir_hash` is stable under formatting changes outside a rule body.
  `lowered_ir_report.accepted_program_digest` goes through the same projection.
  The snapshot keeps its spans: `to_snapshot` is unchanged, all 25 `.ir`
  goldens are byte-identical, and a runtime event is still attributed back to
  source through them.

  Scope, stated because it is narrower than "formatting is free": a reformat
  still mints a new program version. A version row is
  `UNIQUE(program_id, source_hash, ir_hash)` and `source_hash` hashes the
  source TEXT, so whitespace mints a row through `source_hash` whatever
  `ir_hash` does. And a rule's `body_hash` is still a digest of its body TEXT,
  so a blank line *inside* a rule body still moves `ir_hash` — deliberately,
  because inside a `"""` prompt indentation is prose a model reads.

  **This rotates `ir_hash` once, for every program that exists.** It is the
  same cost that was already being paid silently on every span fix, paid once
  deliberately instead, and it lands on the mechanism built for it: a matching
  `source_hash` with a differing `ir_hash` is re-attested with an
  `instance.program.reattested` event, not refused. Which programs compile does
  not change.

### Fixed

- **A `mint` exchange was invisible to the information-flow checker.** It
  shipped two days after `request` and repeated that gap exactly: no
  `resource_for_body` arm, so the token exchange — an egress under the parent
  credential — had no sink and no payload reads. The parent is the sink
  identity, since the child does not exist yet.

  Found by making `check_with_envelope`'s reader-set match **exhaustive**, on
  the model of DR-0074's `collect_effect_binding_roots`: every `IrEffectKind`
  is now named, several with an arm that does nothing and says why, so adding a
  variant is a compile error rather than a silent escape. Writing the `mint`
  arm and noticing it could never fire is what surfaced the missing resource.

  The exhaustive match is a backstop against the next hole, not a fix for the
  remaining ones: an arm only matters if the kind has an IFC resource, and
  seven kinds still have none, so their arms are written and unreachable. That
  is recorded on `spec/flow-checker-resource-kind-tracker.md` with the list,
  rather than left to read as more than it is.

- **A filed tracker issue was invisible to the information-flow checker.**
  DR-0051 §1 gave trackers a *read* side — a `when <tracker> has ready issue`
  trigger keys the bare handle — and never a write side. So a rule could
  `file issue into ops { body charge.note }` with a confidential `charge`, and
  the checker reported nothing at all: a tracker item is a durable surface that
  humans and other agents read.

  A `file issue` is now a write sink keyed by the bare tracker handle, so both
  directions name the same resource, and its field values are recorded as what
  the payload reads. Mutation-verified, with a cleared tracker still compiling
  so the fix cannot degenerate into "deny every filed issue".

  Found by the same method as the `request` hole below, and on the same day:
  enumerating which effect kinds the reader-set classification actually names,
  rather than trusting that its `_ => {}` arm was fail-closed. It is not — an
  unnamed kind is neither a read nor a write. Thirteen of twenty-two kinds are
  still unnamed there; `spec/flow-checker-resource-kind-tracker.md` is reopened
  to carry that, along with `finish item { summary … }`, which names an item
  binding rather than a tracker and so has no statically-known sink.

  A confidential value filed into an unlabelled tracker is newly refused. The
  exits are the usual two: clear the sink, or declassify.

- **`request` was invisible to the information-flow checker.**
  `IrEffectKind::HttpRequest` appeared nowhere in `ifc.rs`, and the parser
  returned no IFC resource for it. The construct that egresses a URL, headers,
  and a body to an arbitrary external host got no reader-set check, no
  `denied flow`, and no entry in the flow graph — a confidential value could be
  sent to an uncleared endpoint and nothing said so. It shipped that way in the
  same release that introduced it.

  A `request` now names its credential as its IFC resource and is classified as
  **both** a read and a write. That is the accurate reading rather than merely
  the conservative one: the payload leaves the process and the response comes
  back. Both directions refuse, and both refusals are mutation-verified.

  The sink identity is the credential handle, not the URL: it is the resource
  the program declares and the one governance grants by identity, so it is what
  an envelope can actually grant. Two requests under one credential to
  different hosts therefore share a sink.

  **A governed program may newly be refused, and that is the fix working.**
  Because a `request` is also a read, what comes back carries the credential's
  reader set: a rule that requests under a `readable by Ops` credential and
  completes a public `result` is now a `denied flow`. The join is per rule, as
  it is for a `file store` read, so the refusal does not ask whether the
  completed value derives from the response. The exits are the same as
  everywhere else — clear the sink, or declassify.

- **A credential reference now has to be one.** `credentials_ref` (provider
  binding config) and `credential_ref` (signed host policy) were free strings
  that nothing parsed. A key pasted into either field validated clean and was
  then written into recorded validation evidence and a canonicalized, signed
  policy envelope — reference-not-value (DR-0053 §2) held by convention only.

  Both now parse. Every spelling the migration recognizes still validates, so
  nothing that was ever a reference is rejected; what is rejected is a value
  that names no scheme.

  The refusal does not echo what it refused, for the same reason: the input
  that reaches that arm is the one most likely to *be* the material, and an
  error string travels into diagnostics, provider reports, and evidence. A test
  in `whipplescript-custody` pins the no-echo property and both call sites
  assert it again.

- **The legacy credential path reports itself as degraded** (DR-0053
  *Migration*). Every credential `whip auth`/`coerce` resolves for itself —
  `OPENAI_API_KEY`, a stored key, the Codex OAuth token — is material whip
  holds in its own process. That is r0, and it is not the same as an r0
  custodian entry, which seals at rest under a passphrase-derived key. Until
  now the two printed identically, so an operator deciding whether their setup
  meets `require credential <rung>` could not tell which one they were running.

  `whip auth status` now carries `credential_ref`, `rung`, and `degraded` in
  its JSON and a second line in its text output, and provider validation
  reports a legacy reference as `credentials_ref_degraded` rather than plain
  `credentials_ref_available`. Legacy still passes — the shim exists so
  existing setups keep working — it just says so.

  A rung is still never claimed from configuration: a `credential:<name>`
  reference reports no rung at all, because only the custodian's derived
  evidence may state one
  (`models/maude/credential-rung-evidence.maude`).

- **The custodian redacts its own material out of an egress response.** An
  endpoint that echoes the credential back — an auth-debug route, a
  misconfigured mirror — returned material that then landed in whip's run
  record, having arrived from *outside*.

  whip cannot fix that: it is designed never to know the material, so it cannot
  recognise it to redact it. The custodian holds both the material and the
  response, so it now redacts on the way back. It records exactly what it put on
  the wire — the presented string, the material as text, and its base64, so a
  `basic` credential and a bare-token echo are both caught — and replaces those
  in the response headers and textual body, longest fragment first.

  `mint`'s exchange deliberately does not scrub: that response is parsed for the
  minted token and never handed back, and scrubbing could corrupt a token
  containing the parent's text.

  Substring redaction only. A response that *transforms* the credential —
  hashing it, returning a prefix — is not caught, and a binary body passes
  through. This is defence in depth behind the type system, not a second
  guarantee.

### Added

- **`obtain credential` — non-blocking governance escalation** (DR-0053 §11).

  ```whip
  obtain credential deploy_key into ops {
    title "deploy_key is not granted"
    body "Deploy blocked: {{ blocked.reason }}"
  } as escalation
  ```

  A rule that discovers it needs authority it was not granted files a tracker
  item and derives a `credential.requested` fact. Nothing waits: the run
  proceeds, or fails on the authority it still does not have, and a later run —
  after a human edited governance — succeeds. A blocking request would be the
  shape the language removed with `ask_human`.

  The fact is what makes it an escalation rather than a notification. It
  carries the credential, the tracker, and the item id, so a rule matching
  `when fact credential.requested as asked` acts on the program's own missing
  authority without re-reading the tracker.

  The tracker is named in the statement, as every tracker write in the language
  is; there is no ambient escalation queue. A credential the program does not
  declare is a check error — the escalation would ask a human for authority no
  rule could use, and would look answered while changing nothing.

- **`secret` carries its credential kind** (DR-0053 §15).

  ```whip
  class ReleaseKeys {
    signing secret<ed25519>
    webhook secret<hmac_sha256>
    anything secret
  }
  ```

  The checks that depend on a credential's kind are keyed by its *name*, and
  each of the four things §5 designs a secret to do — bind, pass, store in a
  record field, sit in an effect position — leaves no name to resolve. The
  discriminant is what a stored secret still carries.

  Bare `secret` stays valid and means "any kind", so there is no source break.
  A kind outside the protocol's closed set is a check error rather than a
  silent widening: widening would hand the author a narrowing they asked for
  and did not get.

  The angle brackets are a built-in constructor, as in `map<string>`, not a
  type parameter — the argument ranges over a closed set of values, not over
  types. Built now because §15 said now: `request` has landed but sentinel
  lowering into value slots has not, so nothing yet produces a secret value in
  an expression. The use-site check that rejects `secret<bearer>` where
  `secret<ed25519>` is required arrives with those values.

- **`request` — authenticated outbound HTTP** (DR-0053 §5).

  ```whip
  credential stripe_api { kind bearer }

  request POST "https://api.stripe.com/v1/refunds" {
    header "Authorization" bearer stripe_api
    header "Idempotency-Key" ticket.id
    body ticket.id
  } as refund
  ```

  whip builds the request with **sentinels** at the marked slots and never with
  material; the custodian substitutes and signs at egress. The request whip
  constructs and records carries a handle, not bytes. Presentation forms are
  `bearer`, `basic`, and `raw`; a handle in a slot is not an expression and
  never reaches the expression checker, because no expression yields material.

  Three compile-time refusals: an undeclared handle, a request that presents
  nothing and signs nothing (`signed with` alone satisfies it — signing *is*
  authentication), and more than one distinct credential in one request, since
  one custody operation carries one credential's material.

  An HTTP error status settles as a **completed** effect carrying the status —
  the endpoint was reached. `after … fails` means whip could not make the call,
  which includes having no custodian configured: that fails loudly rather than
  egressing unauthenticated.

  Spelled `call` in DR-0053 until the 2026-08-25 amendment; `call` was already
  package capability invocation.

  **Known exposure, not solved here.** An endpoint that echoes the credential
  back returns material that lands in the run record. whip cannot redact it —
  it is designed never to know it — so only the custodian can, and it does not
  yet. Recorded on the credential-custody tracker.


### Breaking

- **A grant on a resource your program does not declare is now classified as
  both a read and an egress** (DR-0072).

  The static flow checker classified a grant by its operation verb against two
  closed lists. An operation in neither list contributed nothing, so
  `with access to github { get_issue }` on a `Secret`-labelled server, writing to
  a public store, drew **no diagnostic** — while the same grant spelled
  `github { read }` was denied. Worse than the silence: a server whose tool
  happened to be *named* `get` was classified read-only, a confident answer
  derived from a naming accident in a name the server chooses.

  The verb vocabulary now applies exactly to resources the program declares — a
  `file store`, `tracker`, `ledger`, `channel`, memory pool, counter, lease, or
  stream. Every other resource is foreign, and every grant on one is both
  directions regardless of naming. An unknown operation on a declared resource
  is also both: the checker does not guess.

  **This is accurate, not merely conservative.** A remote tool call ships its
  arguments and returns a result, so it genuinely moves data both ways. The old
  behaviour was not cautious-but-imprecise; it was wrong in the permissive
  direction.

  A program whose foreign-resource grant carries a real unchecked flow now fails
  to build. It was always leaking. Across the workspace suite, 2446 tests pass
  and 0 fail under the rule, and the shipped examples are unaffected because
  they grant on declared file stores. MCP and the `web { search fetch }` grant
  closed together, as they had to — the hole predated MCP.

  What is unchanged: the checker classifies a *grant*, not the journey of a
  value into a particular tool argument.


### Added

- **Tracker-event subscriptions, delivered mid-turn.** An agent can watch a
  tracker queue and learn that another actor claimed or closed an item while it
  is still deciding, instead of discovering the collision when their changes
  meet. Claim is the load-bearing event: an open/closed pair only tells you
  after the wasted work is done.

  Two ways to subscribe, and they write the same durable subscription. An
  embedder names the queues a turn watches with
  `WHIPPLESCRIPT_HARNESS_TRACKER_FEED` (comma-separated); the agent can narrow
  or widen that with the `subscribe_todos` tool, which is governed by its own
  grant — `with access to tracker { subscribe }` (or `watch`). That grant is
  deliberately not implied by `write` or `update`: subscribing is a read, and
  folding it into a write grant would hand every writer a feed it never asked
  for.

  Notices arrive as prose (`WS-12 (title) was claimed by agent:bob`) framed as
  information rather than instruction, matching the existing raise notice —
  mid-turn delivery is another principal's content entering a model's context,
  and a line that read like a directive would be one an attacker could author
  by filing an issue. The rendered event carries the alias, kind, actor, and
  title, and **never** the event payload or issue body, so nothing accumulated
  there can reach a subscriber through this channel.

  The `subscribe` grant does not widen which queues a turn can read: an agent
  may name only its own configured queue and the queues the host declared, and
  any other queue is refused. `list_todos` is scoped to the configured queue, so
  without that confinement the grant would have let an agent watch another
  agent's queue and read its titles, aliases, and actors — a strictly wider read
  than it could perform directly.

  The cursor is a durable per-`(subscriber, queue)` watermark over the local
  event sequence. Subscribing starts at the current head rather than replaying
  a queue's history; re-subscribing never rewinds; a stale advance is a no-op.

  Delivery is owned-harness-only, as DR-0052 has it — coordination granularity
  is a property of the harness, and on the durable object the turn boundary
  remains the atom. The durable-object *store* implements subscriptions at full
  parity regardless, since both hosts share one schema.

### Fixed

- **A non-holder can no longer release or close a claimed tracker item**
  (`tracker-lease.maude` I4). `update_todo` called `finish_item` and
  `release_item` with no holder, and `WorkItems::release_item` took no holder at
  all — it stripped whichever active lease it found. With several agents on one
  tracker, a stale agent could unclaim or close work another agent was still
  doing, and both would then proceed believing they owned the item.

  `release_item` and `finish_item` now take `expect_holder: Option<&str>` and
  return `ReleaseOutcome` / `FinishOutcome` instead of `bool`. `Some(actor)`
  refuses with `HeldByOther { holder }` when a different actor holds the lease,
  and both agent paths pass it — native and durable object alike, because a
  refusal enforced on one host is one an agent evades by running on the other.
  `None` preserves the unconditional behaviour for the operator escape hatch
  (`whip issue release`, `whip issue fail`) and the in-program `release` effect,
  so a stuck lease stays clearable.

  The check runs inside the mutation's own transaction; a caller-side
  read-then-act would be a TOCTOU race against the CAS the lease exists to be.
  It guards against clobbering *another* actor, not against acting on an
  unclaimed item, so closing an unclaimed item still works.

  The lease model had no rule for explicit release at all before this — only
  terminal-release (I3) — so the implementation was less holder-aware than its
  own model. I4 generalizes I2's holder-only renew to any holder-scoped lease
  mutation.

  **Breaking for embedders** implementing `WorkItems` or calling either method:
  both signatures gained a parameter and both return types changed.

## Maintenance releases

Fixes cut on a support branch for a consumer pinned to an older line, while
`main` had moved past it. These are **not** steps in the version ladder — `main`
never passed through them — so they are listed here rather than as ladder
entries. They are published to crates.io only: no GitHub Release, no Homebrew
formula, no platform archives. Policy: `spec/release-checklist.md`
§"Maintenance releases off a support branch".

- **`0.4.2`** — 2026-08-17, branch `v0.4.x`, tag `v0.4.2` (`-src` only). Partial
  by design: `whipplescript` and `whipplescript-store` only; `whipplescript-core`,
  `-parser`, and `-kernel` remain at `0.4.1`, and the branch's workspace version
  still reads `0.4.1`. Carries the contended-store-write wait and the native
  answer-delta seam backport (#196). Recorded retroactively 2026-08-25.

## [0.5.6] — 2026-08-24

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
- Entries for `0.2.2`, `0.2.3`, `0.3.0`, and `0.3.1` were not written at their
  cuts. They were **backfilled 2026-08-24** from the annotated tag messages,
  which carry each cut's own release notes verbatim; the reasoning is unchanged,
  only relocated to where a reader looks for it.

## [0.3.1] — 2026-07-28

The `0.3.0` content, published under the next free number.

### Notes
- **Version only.** crates.io holds a yanked `whipplescript-core 0.3.0` from an
  earlier stale publish and will not let the number be reused, so the whole
  chain skips to `0.3.1` rather than letting `core` drift a version ahead of the
  crates that depend on it. The code is `0.3.0`'s; see that entry for what
  changed.

## [0.3.0] — 2026-07-28

`ask_human` is removed (DR-0050).
Published as `0.3.1` — see that entry.

### Breaking
- **`ask_human` is gone** — the tool and its spec, the `human_interaction` flag,
  `TurnStatus::AwaitingHuman`, `PendingHumanRequest`, `answer_human` on the turn
  machine and snapshot, and `HumanAnswerCommand`; on the durable-object side
  `inbox_items`, `do_record_human_ask`, `do_mark_human_answered`, the
  `/host/instances/*/human/answer` route, the pending projection, and the
  `human_ask` session frame. A turn now has four terminals and no fifth parked
  state.

  It let an agent stop mid-turn and wait for a person, and it was the wrong
  shape twice over. It never said who or where — "ask a human" assumes an
  ambient person attached to the running turn, which is false wherever no such
  person exists and under-specified where one does. And it conflated
  communication with control flow: asking is communication, waiting is control
  flow, and fusing them produced a mechanism that held a model conversation open
  indefinitely, survived restarts only through a bespoke snapshot path built to
  make it, and could be answered by exactly one party.

  The language already has both halves, and they name their destinations:
  `send via <channel>` with a `when message from` rule for communication, and
  `file issue into <tracker>` with `claim` for work assignment. Neither blocks a
  turn.

  This invalidates live sessions, the same way DR-0049's bootstrap change did.

### Fixed
- **A durable-object route that was already dead.** The worker's
  `host_answer_human_ask` and `host_validate_human_answer` called wasm exports
  the Rust side never had, so that route would have thrown if reached.
- The `/pending` route stays, answering `{pending: null}`, so a client from
  before the cutover gets a well-formed answer rather than a 404.

### Documented
- Docs stopped linking to `spec/` files the public repository never publishes,
  and the three retired page paths gained redirect stubs.

## [0.2.3] — 2026-07-27

The std manifests become reachable from the library, not just the binary.

### Fixed
- **`EMBEDDED_STD_MANIFESTS` moves to `whipplescript::std_manifests`**, with
  `register_all` for the seeding loop every host would otherwise write. It was
  declared in `main.rs`, so only the binary could seed the std package rows.
  That was survivable until `0.2.2` made the admission gate real for
  `std.files` / `std.coord` / `std.tracker` / `std.ingress`: an effect whose
  capability rows were never seeded then blocks as `blocked_by_capability`, so
  an embedding host running a *workflow* — rather than only an agent turn —
  could not run governed effects at all.

  This is the case `lib.rs` exists for: the CLI and embedding hosts cross the
  same governance boundary, and a host that cannot reach the seeding code either
  fails or writes its own and drifts from what `whip` does. The vendored files
  already sat in this crate, so the `include_str!` paths are unchanged, the root
  `std/` stays the source of truth, and `scripts/check-vendored-std.sh` still
  passes.

## [0.2.2] — 2026-07-27

Tracker issues can say who should act on them.

### Added
- **Optional issue assignment** — `WorkItem.assigned_to`, a durable
  `assigned_to` column, an `issue.assigned` event, `assign_item(id, Option<who>)`
  on the store and the `WorkItems` trait, and `whip issue assign <id> [--to A |
  --clear]`.

  Assignment is **advisory**: it records who *should* act and never restricts
  who *may* claim. Enforcing it would need an authority model, and this crate
  deliberately has none — the assignee is an opaque string the embedding host
  interprets. So assignment and claim stay distinct facts: an assignment is
  durable and visible before anyone responds, a claim is the transient CAS that
  decides who is acting. An unassigned issue means "whoever has access", which
  is the ordinary case rather than an omission.

  This is what `askHuman` lacked — directing work at a named party on a named
  tracker is exactly what its deprecation asks callers to say explicitly, and
  until now the tracker had no field to say it in.

### Fixed
- **Two migration paths, because there are two stores.** The native store
  self-heals through the existing `tx_ensure_column`. The durable object does
  not — its `ensureSchema` applies the schema only when `schema_migrations` is
  absent, so every already-created object would have failed its next tracker
  read on a missing column. It gets a lazy `ALTER TABLE` beside the additive
  block that already does this for `host_turn_images`. The production
  `do_schema.sql` and the in-memory test fixture are separate files; both carry
  the column.

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
