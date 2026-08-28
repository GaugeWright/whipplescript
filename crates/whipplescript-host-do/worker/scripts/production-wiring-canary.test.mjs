import assert from "node:assert/strict";
import test from "node:test";

import {
  runManagedHost,
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
