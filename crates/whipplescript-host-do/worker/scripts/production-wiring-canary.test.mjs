import assert from "node:assert/strict";
import { createECDH, createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import test from "node:test";

import {
  NORM_LEDGER_HISTORY_LIMIT,
  NORM_LEDGER_PROMOTION,
  NORM_LEDGER_ROUTES,
  normLedgerRequests,
  runManagedHost,
  runNormLedger,
  runPrivateHome,
} from "./production-wiring-canary.mjs";

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

const signedPolicy = JSON.stringify({
  attestation: {
    algorithm: "p256-sha256",
    envelope_hash: "a".repeat(64),
    key_id: "governance-key",
    signature: "signature",
    signer: "synthetic-governance",
  },
  bindings: { do: "placement:do", model: "provider:openai" },
  declassifications: [],
  delegations: [],
  endorsements: [],
  parties: {},
  placements: {
    do: { kind: "durable_object", provider_bindings: ["model"] },
  },
  provider_bindings: {
    model: {
      base_url: "https://api.openai.com/v1/responses",
      credential_ref: "managed-openai",
      model: "gpt-test",
      provider: "openai",
    },
  },
  resources: {},
});

test("managed canary crosses placement forwarding and restores its baseline", async () => {
  const calls = [];
  let positions = 0;
  const fetchImpl = async (url, init) => {
    const parsed = new URL(url);
    const path = parsed.pathname.replace(
      "/v1/tenants/synthetic-tenant/placements/synthetic-placement",
      "",
    );
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ path, method: init.method ?? "GET", headers: new Headers(init.headers), body });
    if (!new Headers(init.headers).has("authorization")) return json({ error: "unauthorized" }, 401);
    if (path === "/host/policy") {
      return json({
        epoch: 1,
        envelope_hash: "a".repeat(64),
        signer: "synthetic-governance",
        key_id: "governance-key",
      }, 201);
    }
    if (path === "/host/instances/open") {
      return json({ instance_ref: "instance:synthetic", opened_at: { sequence: 1 } }, 201);
    }
    if (path.endsWith("/checkpoint") || path.endsWith("/restore")) {
      return json({ ok: true });
    }
    if (path.endsWith("/files/sync")) {
      return json({ synced: body.files.length });
    }
    if (path.endsWith("/position")) {
      positions += 1;
      return json({ instance_ref: "instance:synthetic", sequence: positions === 1 ? 2 : 8 });
    }
    if (path === "/host/turns") {
      return json({ admitted: true, command_id: body.command.command_id });
    }
    if (path.endsWith("/stream") && path.includes("/turns/")) {
      return new Response("data: {\"delta\":\"wired\"}\n\n", {
        headers: { "content-type": "text/event-stream" },
      });
    }
    if (path.endsWith("/events/stream")) {
      return new Response("event: runtime\ndata: {}\n\n", {
        headers: { "content-type": "text/event-stream" },
      });
    }
    if (path.endsWith("/fork-export")) return json({ schema: "fork" });
    if (path === "/host/forks/import") {
      return json({ target: { instance_ref: "instance:synthetic-fork" } }, 201);
    }
    if (path.endsWith("/discard")) {
      return json({
        instance_ref: body.command.instance_ref,
        discarded_at: { instance_ref: body.command.instance_ref, sequence: 4 },
      });
    }
    if (path.endsWith("/cancel")) {
      return json({ command_id: body?.command_id, status: "requested" }, 202);
    }
    throw new Error(`unexpected ${init.method ?? "GET"} ${path}`);
  };
  const liveCalls = [];
  const result = await runManagedHost({
    GW_SYNTHETIC_WHIP_MANAGED_ORIGIN: "https://runtime.example.test",
    GW_SYNTHETIC_WHIP_CONTROL_TOKEN: "control-token",
    GW_SYNTHETIC_WHIP_TENANT: "synthetic-tenant",
    GW_SYNTHETIC_WHIP_PLACEMENT: "synthetic-placement",
    GW_SYNTHETIC_WHIP_SIGNED_POLICY: signedPolicy,
  }, fetchImpl, async (url, token) => {
    liveCalls.push({ url, token });
    return { firstMessage: { type: "runtime_events" }, close() {} };
  });

  assert.equal(result.instance, "instance:synthetic");
  assert.equal(liveCalls.length, 1);
  assert.match(liveCalls[0].url, /^wss:\/\//);
  assert.equal(liveCalls[0].token, "control-token");
  assert(calls.some((call) => call.path === "/host/policy" && call.method === "POST"));
  assert(calls.some((call) => call.path.endsWith("/events/stream")));
  assert(calls.some((call) => call.path === "/host/forks/import"));
  assert(calls.some((call) => call.path.endsWith("/cancel")));
  assert(calls.some((call) => call.path.endsWith("/restore")));
  assert.deepEqual(calls.at(-1).body, { files: [], delete_missing: true });
  assert(
    calls.filter((call) => call.headers.has("authorization"))
      .every((call) => call.headers.get("authorization") === "Bearer control-token"),
  );
});

test("Private Home canary denies missing and tampered grants before forwarding", async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const calls = [];
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname;
    const headers = new Headers(init.headers);
    calls.push({ path, method: init.method, headers, body: init.body });
    if (!headers.has("x-gaugewright-execution-grant")) {
      return json({ error: "grant required" }, 401);
    }
    if (String(init.body ?? "").endsWith(" ")) {
      return json({ error: "body mismatch" }, 403);
    }
    if (path.endsWith("/host/policy")) {
      const body = JSON.parse(init.body);
      const envelope = JSON.parse(body.signed_envelope);
      return json({
        epoch: body.epoch,
        envelope_hash: envelope.attestation.envelope_hash,
        signer: envelope.attestation.signer,
        key_id: envelope.attestation.key_id,
      }, 201);
    }
    if (path.endsWith("/host/instances/open")) {
      return json({ instance_ref: "instance:private-synthetic" }, 201);
    }
    if (path.endsWith("/position")) {
      return json({ instance_ref: "instance:private-synthetic", sequence: 1 });
    }
    throw new Error(`unexpected ${init.method} ${path}`);
  };

  const result = await runPrivateHome({
    GW_SYNTHETIC_WHIP_PRIVATE_ORIGIN: "https://private-runtime.example.test",
    GW_SYNTHETIC_WHIP_PRIVATE_HOME: "home-synthetic",
    GW_SYNTHETIC_WHIP_PRIVATE_TENANT: "tenant-synthetic",
    GW_SYNTHETIC_WHIP_PRIVATE_PROJECT: "project-synthetic",
    GW_SYNTHETIC_WHIP_PRIVATE_GOVERNANCE_SIGNER: "home-authority-synthetic",
    GW_SYNTHETIC_WHIP_PRIVATE_SIGNER_JWK: JSON.stringify(privateJwk),
  }, fetchImpl);

  assert.equal(result.instance, "instance:private-synthetic");
  assert.equal(calls[0].headers.has("x-gaugewright-execution-grant"), false);
  assert.equal(calls[1].headers.has("x-gaugewright-execution-grant"), true);
  assert.equal(calls[1].headers.has("authorization"), false);
  assert(calls.some((call) => call.method === "GET" && call.path.endsWith("/position")));
  assert(
    calls.filter((call) => call.headers.has("x-gaugewright-execution-signature"))
      .every((call) => call.headers.get("x-gaugewright-execution-signature").length > 40),
  );
});

// --- norm-ledger ------------------------------------------------------------

// A valid P-256 point for the sample publisher, so the Rust decode test can
// bind it in its trust document. Deterministic: the scalar is fixed.
function samplePoint(byte) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.alloc(32, byte));
  return ecdh.getPublicKey("hex", "uncompressed");
}

// The identities a provisioned synthetic ledger hands the suite. The vector
// below pins the requests built from exactly these.
const normWorkspace = {
  instance: "norm-ledger-canary-instance",
  run: "norm-ledger-canary-run",
  requirement: "a".repeat(64),
  cut: "norm-ledger-canary-cut",
  effect: "norm-ledger-canary-effect",
  capability: "observer",
  vocabulary: "local-observation@1",
  publisher: {
    principal: "norm-ledger-canary-publisher",
    algorithm: "p256-sha256",
    key_id: samplePoint(7),
  },
  impact: { before_cut: "norm-ledger-canary-before", after_cut: "norm-ledger-canary-after" },
  promotion: { stream: "norm-ledger-canary-stream", tokens: [] },
};

const normAct = {
  statement: {
    protocol: "whipplescript.norm/v1",
    actor: { principal: "norm-ledger-canary-owner", algorithm: "p256-sha256", key_id: samplePoint(9) },
    nonce: "production-norm-ledger-canary:genesis:v1",
    created_at: "2026-09-28T00:00:00Z",
    action: {
      act: "bootstrap",
      creator: "norm-ledger-canary-worker",
      charter: { vocabularies: [], owner_scopes: [] },
    },
  },
  signature: "5".repeat(128),
};

const normEnvironment = {
  GW_SYNTHETIC_WHIP_MANAGED_ORIGIN: "https://runtime.example.test",
  GW_SYNTHETIC_WHIP_CONTROL_TOKEN: "control-token",
  GW_SYNTHETIC_WHIP_TENANT: "synthetic-tenant",
  GW_SYNTHETIC_NORM_PLACEMENT: "synthetic-norm-ledger",
  GW_SYNTHETIC_NORM_SIGNED_ACT: JSON.stringify(normAct),
  GW_SYNTHETIC_NORM_WORKSPACE: JSON.stringify(normWorkspace),
};

const normRoot = "/v1/tenants/synthetic-tenant/placements/synthetic-norm-ledger/host/norm/";
const hex = (value) => createHash("sha256").update(value).digest("hex");

// The deployed doors as far as the suite can observe them: an append-only
// history keyed by content, retained publication, idempotent enqueue and
// promotion. Knobs model each way the suite must fail instead of passing.
function normLedgerDouble(options = {}) {
  const ledger = hex("genesis");
  const provisioned = [{ event_id: ledger }];
  const history = [...provisioned, ...(options.history ?? [])];
  const observation = {
    statement: {
      protocol: "whipplescript.norm/v1",
      actor: normWorkspace.publisher,
      nonce: "observation",
      created_at: "2026-09-27T00:00:00Z",
      action: { act: "create", ledger },
    },
    signature: "6".repeat(128),
  };
  const calls = [];
  let appends = 0;
  const reply = (body, status = 200) => new Response(JSON.stringify(body), {
    status, headers: { "content-type": "application/json" },
  });
  const refuse = (error) => reply({ error }, 400);
  const fetchImpl = async (url, init) => {
    const parsed = new URL(url);
    const headers = new Headers(init.headers);
    const body = JSON.parse(init.body);
    calls.push({ path: parsed.pathname, method: init.method, headers, body });
    assert(parsed.pathname.startsWith(normRoot), `unexpected path ${parsed.pathname}`);
    const route = parsed.pathname.slice(normRoot.length);
    const authorized = headers.get("authorization") === "Bearer control-token";
    if (!authorized) return options.openEdge ? reply({}) : reply({ error: "unauthorized" }, 401);
    if (route === "provision") {
      if (Object.keys(body).length) return refuse("norm provisioning request must be an empty object");
      return reply({ checkpoint: { ledger, authority_head: ledger } });
    }
    if (route === "commands") {
      if (body.bindings) return refuse("unknown field `bindings`");
      if (body.command.kind === "export") {
        const events = options.forget && calls.filter((call) => call.body?.command?.kind === "export").length > 3
          ? history.slice(1) : history;
        return reply({ protocol: body.protocol, result: {
          kind: "exported", checkpoint: { ledger, authority_head: ledger },
          frontier: [events.at(-1).event_id], events,
        } });
      }
      if (body.command.kind === "append") {
        if (body.command.event.signature === "00") return refuse("norm P-256 signature is not raw fixed-width ECDSA");
        appends += 1;
        const id = hex(JSON.stringify(body.command.event) + (options.fresh ? appends : ""));
        if (!history.some((event) => event.event_id === id)) history.push({ event_id: id });
        return reply({ protocol: body.protocol, result: { kind: "appended", event_id: id } });
      }
    }
    if (route === "impacts") {
      if (body.deployment) return refuse("unknown field `deployment`");
      return reply({ protocol: body.protocol, result: { plan: {
        time_basis: `hosted-impact/${Date.now()}/${crypto.randomUUID()}`, requirements: {},
      } } });
    }
    if (route === "enqueues") {
      if (body.command.publisher !== normWorkspace.publisher.principal) {
        return refuse("norm enqueue publisher has no deployment binding");
      }
      return reply({ protocol: body.protocol, result: {
        acknowledgment: { event_id: "evt_0", sequence: 3 },
        effect_id: body.command.effect, anchor: { frontier: [ledger] }, artifact: {},
      } });
    }
    if (route === "publications") {
      if (body.command.kind === "prepare") {
        return reply({ protocol: body.protocol, result: options.unpublished
          ? { kind: "unsigned", statement: observation.statement }
          : { kind: "retained", event: observation } });
      }
      if (body.command.event.signature === "invalid") return refuse("norm P-256 signature is not hex");
      const id = hex(JSON.stringify(body.command.event));
      if (!history.some((event) => event.event_id === id)) history.push({ event_id: id });
      return reply({ protocol: body.protocol, result: {
        event_id: id, acknowledgment: { event_id: "evt_1", sequence: 4 }, observation: {},
      } });
    }
    if (route === "promotions") {
      if (body.deployment) return refuse("unknown field `deployment`");
      return reply({ protocol: body.protocol, result: {
        promoted: body.command.stream, into: "main", receipt: { cut: "promoted" },
      } });
    }
    throw new Error(`unexpected ${init.method} ${parsed.pathname}`);
  };
  return { fetchImpl, calls, history };
}

test("norm-ledger canary answers every door, refuses bad credentials, and adds only its one act", async () => {
  const double = normLedgerDouble();
  const first = await runNormLedger(normEnvironment, double.fetchImpl);
  const grown = double.history.length;
  const second = await runNormLedger(normEnvironment, double.fetchImpl);

  assert.deepEqual(second, first, "a re-run was not an exact retry");
  assert.equal(double.history.length, grown, "a re-run added history");
  // Provisioned genesis, the canary's act, and the retained observation.
  assert.equal(first.history, 3);
  assert.equal(first.effect, normWorkspace.effect);
  assert.equal(first.promoted, normWorkspace.promotion.stream);

  // Every call is a POST to one of the six doors of the dedicated placement.
  // No restore, discard, erase, or any other route: norm history is append-only
  // and this suite's cleanup is that every request is an exact retry.
  const routes = new Set();
  for (const call of double.calls) {
    assert.equal(call.method, "POST");
    const route = call.path.slice(normRoot.length);
    assert(NORM_LEDGER_ROUTES.includes(route), `called ${call.path}`);
    routes.add(route);
    assert.equal(call.headers.get("content-type"), "application/json");
  }
  assert.deepEqual([...routes].sort(), [...NORM_LEDGER_ROUTES].sort());

  // Each door was denied without a token and with a wrong one, carrying a body
  // no door but provision decodes.
  for (const route of NORM_LEDGER_ROUTES) {
    const denials = double.calls.filter((call) =>
      call.path.endsWith(`/${route}`) && call.headers.get("authorization") !== "Bearer control-token");
    assert.deepEqual(
      denials.map((call) => call.headers.get("authorization")).slice(0, 2),
      [null, "Bearer control-token.invalid"],
      `${route} denials`,
    );
    assert(denials.every((call) => JSON.stringify(call.body) === "{}"));
  }
  const authorized = double.calls.filter((call) => call.headers.has("authorization"));
  assert(authorized.every((call) =>
    ["Bearer control-token", "Bearer control-token.invalid"].includes(call.headers.get("authorization"))));

  // The signed act is sent byte-for-byte as provisioned: the runner re-signs nothing.
  const appends = double.calls.filter((call) =>
    call.body?.command?.kind === "append" && call.body.command.event.signature !== "00");
  assert.equal(appends.length, 4);
  assert(appends.every((call) => JSON.stringify(call.body.command.event) === JSON.stringify(normAct)));
  // The only provision with a body is the refusal probe; the only checkpoint
  // the suite ever sends is one the door must refuse.
  const provisions = double.calls.filter((call) =>
    call.path.endsWith("/provision") && call.headers.get("authorization") === "Bearer control-token");
  assert.deepEqual(provisions.map((call) => Object.keys(call.body)), [[], ["checkpoint"], [], ["checkpoint"]]);
  const promotions = double.calls.filter((call) => call.body?.command?.promotion);
  assert(promotions.every((call) => call.body.command.promotion === NORM_LEDGER_PROMOTION));
});

test("norm-ledger canary fails when a door admits a missing token", async () => {
  await assert.rejects(
    runNormLedger(normEnvironment, normLedgerDouble({ openEdge: true }).fetchImpl),
    /commands admitted a missing control token/,
  );
});

test("norm-ledger canary fails when a retry mints a new event", async () => {
  await assert.rejects(
    runNormLedger(normEnvironment, normLedgerDouble({ fresh: true }).fetchImpl),
    /exact retry of the signed act is a different receipt/,
  );
});

test("norm-ledger canary will not publish an observation it would have to sign", async () => {
  const double = normLedgerDouble({ unpublished: true });
  await assert.rejects(
    runNormLedger(normEnvironment, double.fetchImpl),
    /never been published/,
  );
  assert(!double.calls.some((call) => call.body?.command?.kind === "publish"));
});

test("norm-ledger canary fails when history is unbounded or loses an event", async () => {
  const history = Array.from({ length: NORM_LEDGER_HISTORY_LIMIT }, (_, index) => ({ event_id: hex(`e${index}`) }));
  await assert.rejects(
    runNormLedger(normEnvironment, normLedgerDouble({ history }).fetchImpl),
    /bounded at 256/,
  );
  await assert.rejects(
    runNormLedger(normEnvironment, normLedgerDouble({ forget: true }).fetchImpl),
    /append-only/,
  );
});

test("norm-ledger canary refuses malformed synthetic identities before calling anything", async () => {
  const double = normLedgerDouble();
  for (const [name, value, pattern] of [
    ["GW_SYNTHETIC_NORM_SIGNED_ACT", "{}", /no norm statement/],
    ["GW_SYNTHETIC_NORM_WORKSPACE", JSON.stringify({ ...normWorkspace, vocabulary: "unversioned" }), /name@version/],
    ["GW_SYNTHETIC_NORM_WORKSPACE", JSON.stringify({ ...normWorkspace, effect: "has space" }), /effect is invalid/],
    ["GW_SYNTHETIC_NORM_WORKSPACE", undefined, /GW_SYNTHETIC_NORM_WORKSPACE is required/],
  ]) {
    await assert.rejects(runNormLedger({ ...normEnvironment, [name]: value }, double.fetchImpl), pattern);
  }
  assert.equal(double.calls.length, 0);
});

// The Rust doors decode exactly these bodies:
// `norm_ledger_canary_requests_decode_at_every_hosted_door` reads this vector.
// Regenerate with WHIPPLESCRIPT_WRITE_NORM_CANARY_VECTOR=1 after changing a request.
const vectorPath = new URL("./fixtures/norm-ledger-canary-requests.json", import.meta.url);
test("the norm-ledger request vector is what the runner sends", async () => {
  const vector = {
    protocol: "whipplescript.production-canary.norm-ledger-requests/v1",
    workspace: normWorkspace,
    // The signed act and retained observation are forwarded verbatim, so the
    // vector pins the envelope around them and the Rust test supplies them.
    requests: normLedgerRequests(normWorkspace, null, null),
  };
  const text = `${JSON.stringify(vector, null, 2)}\n`;
  if (process.env.WHIPPLESCRIPT_WRITE_NORM_CANARY_VECTOR === "1") await writeFile(vectorPath, text);
  assert.equal(await readFile(vectorPath, "utf8"), text);
});
