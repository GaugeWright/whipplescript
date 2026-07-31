# WhippleScript runtime — Cloudflare Worker + Durable Object shell (DR-0033 chunk 5d)

This is the **live-deployment shell** for the sans-IO runtime. The Rust core
(`crate whipplescript-host-do`) is compiled to wasm and exposes
`WasmDurableInstance` (`create` / `attach_host` / `step` / `status`). The shell
also exposes the authenticated `whipplescript.host.v1` placement API: signed
policy bootstrap, package/instance open, workspace sync and projection,
turn/cancel/result, evidence/events, and checkpoint/restore.

## What is done vs. what needs a deployment

Everything in Rust is built, proven against a real SQLite engine (native + wasm),
and wasm-clean: the instance scheduler, the store, every effect family, both HTTP
effects (sans-IO suspend/resume), eviction-safe agent turns, the
`create`/`step`/`status` handle, and the `#[wasm_bindgen]` surface. `src/index.ts`
+ `wrangler.toml` are the shell that plugs those into a live Durable Object.

**Chunk 5d — live validation — is the only step that cannot happen in-repo.** It
needs a Cloudflare account and:

## Deploy steps

**One command:** `whip deploy` (compute plane P8) runs the whole sequence
below — dependency install, wasm build, host-boundary secret provisioning, and
the wrangler deploy. `--dry-run` validates the bundle
without publishing; `--worker-dir`/`WHIPPLESCRIPT_WORKER_DIR` point it at
this directory when running outside the repo. The manual steps, for
reference:

1. **Build the wasm module** (from the `#[wasm_bindgen]` surface):
   ```
   npm install
   npm run build:wasm      # wasm-pack build .. --target bundler --out-dir worker/pkg
   ```
2. **Apply the runtime schema to the DO SQLite.** The DO's SQLite must carry the
   runtime store schema (`crates/whipplescript-store/migrations/0001_runtime_store.sql`,
   the same schema `do_store.rs` is ported against). Run it once on object init
   (embed the SQL and `sql.exec` it before `create`, or ship it as a DO migration).
3. **Choose provider egress** (for governed host turns). Brokered turns need no
   provider map: after admission the Worker uses the exact provider, model,
   endpoint, and credential ref from the signed policy epoch. Set only the
   broker transport:
   ```
   wrangler secret put WHIP_MODEL_BROKER_TOKEN
   # Set non-secret WHIP_MODEL_BROKER_URL in wrangler configuration.
   ```
   Governed host turns have no static provider map or provider-secret binding.
   Broker failure is fail-closed; the Worker never falls back to direct provider
   egress.

   Public sessions use direct provider egress. The final-fetch boundary
   resolves the exact credential ref admitted by the deployment through the
   `PUBLIC_CREDENTIALS` Durable Object binding and verifies its provider and
   non-secret credential class before replacing the authentication sentinel.
   There is no static credential map or `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`
   fallback.

   For a remote-DO development turn using GaugeDesk's locally sealed Codex
   login, point the same broker variables at the authenticated outbound tunnel's
   `/internal/local-model-egress` route. The Worker retains only the hop token
   and broker sentinel; GaugeDesk refreshes and injects the short-lived access
   token and account id locally.
4. **Deploy**: `npm run deploy` (`wrangler deploy`).

## Private Home runtime

`wrangler.private-staging.toml` is the unpublished managed-Machine Durable
workflow composition. It reuses `WorkflowInstance`, but its entrypoint accepts
only exact `/v1/homes/.../commands/.../attempts/.../host/...` requests carrying
a short-lived P-256 Home grant. The grant binds the Home, tenant, project,
work-target basis, command, epoch, package, capabilities, request method/path,
and request-body digest.

This composition intentionally has no public-session admission, deployment,
collection, public credential, executor-container, or public route binding.
Set `WHIP_CONTROL_TOKEN` (internal Worker-to-object authentication),
`HOME_ADMISSION_KEYS` (a JSON map of Home key ids to public P-256 JWKs), and
the private model-broker configuration before running
`npm run deploy:private-staging`.

`npm run test:private-staging` proves unauthorized, tampered, and correctly
signed-but-invalid policy handling. To prove real Durable Object persistence
across an isolate replacement, run `test:private-staging:open -- <state-file>`,
redeploy the same Worker, then run
`test:private-staging:resume -- <state-file>`. The state file contains only
public command, package, policy, instance, and position evidence; the signer JWK
is supplied separately as `MACHINE_STAGING_SIGNER_JWK`.
5. **Validate**: use the canonical managed route
   `/v1/tenants/:tenant/placements/:placement/host/...` (Bearer
   `WHIP_CONTROL_TOKEN`), or `POST /start` for the legacy workflow surface, and confirm the
   instance drives to `completed` — an effect-free workflow in one `step`, a coerce/
   agent workflow across `needs_http` rounds.

## Regenerating the cross-language collection vector

GaugeDesk's Rust opener must decrypt what this object seals, and the only honest
way to check that is to hand it bytes this object actually emitted:

```
npm run capture:collection-vector   # writes ./collection-emitted-vector.json
```

It runs the `emitCollection` integration test under workerd and writes the
deposited artifact — envelope, ciphertext, wraps, and the recipient's private
half — to disk. Copy the file to
`gaugedesk/crates/app/tests/collection-emitted-vector.json`; that is where the
opener that has to agree with it lives, and where the vector is committed.

The capture is deliberately opt-in via `COLLECTION_VECTOR_OUT`: an ordinary
`npm test` must not rewrite a committed vector, or the vector stops being a fixed
point anyone reviewed. A wholesale rewrite of the file is a claim that the seal
changed; review it as one.

## The integration contract (three seams)

- **`DoSqlBridge` → `state.storage.sql`** — `makeBridge` in `index.ts`. Rows come
  back positionally (`Object.values`, column order preserved per Cloudflare docs).
- **`DurableEffectPorts` → admitted provider realization** — governed host turns
  dynamically resolve the signed provider tuple to the fixed non-secret
  authentication sentinel. Public direct-provider credentials remain Worker
  bindings and are read only by the final-fetch boundary; they never enter
  `DurableEffectPorts`, Wasm configuration, snapshots, or durable records. The
  binding id + release credential class are admitted by the signed policy; the
  public session separately supplies its deployment's exact opaque credential
  ref. Both provider and class must match that exact registry entry before
  egress is available.
- **`needs_http` → egress** — `performFetch` handles direct/container rounds;
  `performModelBrokerFetch` strips sentinel auth and sends private-host requests
  through the authenticated `whipplescript.model-egress.v1` broker envelope;
  `performDirectProviderFetch` strips the same sentinel, injects the exact
  public credential at the last moment, and fetches the signed provider endpoint
  directly.

Once these are wired and the object deployed, 5d is exercising already-proven Rust.
