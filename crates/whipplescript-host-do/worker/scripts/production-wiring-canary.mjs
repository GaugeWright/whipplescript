#!/usr/bin/env node

import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import WebSocket from "ws";

const encoder = new TextEncoder();
const hostProtocol = "whipplescript.host.v1";

function required(environment, name) {
  const value = environment[name]?.trim();
  assert(value, `${name} is required`);
  return value;
}

function exactOrigin(environment, name) {
  const origin = new URL(required(environment, name));
  assert.equal(origin.protocol, "https:", `${name} must use HTTPS`);
  assert.equal(origin.pathname, "/", `${name} must not contain a path`);
  origin.search = "";
  origin.hash = "";
  return origin.href.replace(/\/$/, "");
}

function boundedId(environment, name, fallback) {
  const value = environment[name]?.trim() || fallback;
  assert.match(value, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/, `${name} is invalid`);
  return value;
}

async function sha256Hex(value) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(value)))
    .toString("hex");
}

async function packageDocuments() {
  const source = `workflow Published {
  agent assistant {
    provider owned
    profile "repo-reader"
    capacity 1
    capabilities []
  }
  rule converse when started => {
    tell assistant "Answer with the single word wired."
  }
}`;
  const manifest = JSON.stringify({
    schema: "whipplescript.agent_package.v0",
    source: "agent.whip",
    workflow: "Published",
    agent: "assistant",
    system_prompt: "persona.md",
    capabilities: [],
    agent_abilities: [],
    max_steps: 4,
  });
  const system_prompt = "Return only bounded synthetic wiring output.";
  const version = await sha256Hex(JSON.stringify({ manifest, source, system_prompt }));
  return {
    manifest,
    source,
    system_prompt,
    version_ref: `whip:agent-package:${version}`,
  };
}

async function responseJson(response, label) {
  const text = await response.text();
  assert(text.length <= 1_000_000, `${label} returned an oversized response`);
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    assert.fail(`${label} returned non-JSON`);
  }
}

function assertStatus(response, accepted, label) {
  assert(
    accepted.includes(response.status),
    `${label} returned ${response.status}`,
  );
}

function defaultLiveSocket(url, token) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, {
      headers: { authorization: `Bearer ${token}` },
      handshakeTimeout: 30_000,
    });
    const timeout = setTimeout(() => {
      socket.terminate();
      reject(new Error("managed event WebSocket returned no initial projection"));
    }, 30_000);
    const cleanup = () => clearTimeout(timeout);
    socket.once("message", (data) => {
      cleanup();
      try {
        const firstMessage = JSON.parse(String(data));
        resolve({
          firstMessage,
          close: () => socket.close(1000, "production wiring complete"),
        });
      } catch {
        socket.terminate();
        reject(new Error("managed event WebSocket returned non-JSON"));
      }
    });
    socket.once("error", (error) => {
      cleanup();
      reject(error);
    });
  });
}

function managedPolicy(environment) {
  const signedEnvelope = required(environment, "GW_SYNTHETIC_WHIP_SIGNED_POLICY");
  let envelope;
  try {
    envelope = JSON.parse(signedEnvelope);
  } catch {
    assert.fail("GW_SYNTHETIC_WHIP_SIGNED_POLICY is not JSON");
  }
  const attestation = envelope?.attestation;
  assert.match(attestation?.envelope_hash ?? "", /^[0-9a-f]{64}$/);
  assert.equal(typeof attestation?.signer, "string");
  assert.equal(typeof attestation?.key_id, "string");
  const bindings = Object.entries(envelope?.provider_bindings ?? {});
  assert(bindings.length > 0, "synthetic host policy has no provider binding");
  const [providerBindingRef, provider] = bindings[0];
  assert.equal(typeof provider?.credential_ref, "string");
  const placements = Object.keys(envelope?.placements ?? {});
  assert(placements.length > 0, "synthetic host policy has no placement");
  return {
    epoch: Number(environment.GW_SYNTHETIC_WHIP_POLICY_EPOCH?.trim() || "1"),
    signedEnvelope,
    ref: {
      epoch: Number(environment.GW_SYNTHETIC_WHIP_POLICY_EPOCH?.trim() || "1"),
      envelope_hash: attestation.envelope_hash,
      signer: attestation.signer,
      key_id: attestation.key_id,
    },
    providerBindingRef,
    credentialRef: provider.credential_ref,
    placementRef: placements[0],
  };
}

export async function runManagedHost(
  environment = process.env,
  fetchImpl = fetch,
  openLiveSocket = defaultLiveSocket,
) {
  const origin = exactOrigin(environment, "GW_SYNTHETIC_WHIP_MANAGED_ORIGIN");
  const token = required(environment, "GW_SYNTHETIC_WHIP_CONTROL_TOKEN");
  const tenant = boundedId(environment, "GW_SYNTHETIC_WHIP_TENANT", "synthetic-wiring");
  const placement = boundedId(
    environment,
    "GW_SYNTHETIC_WHIP_PLACEMENT",
    "production-wiring-canary-v1",
  );
  const policy = managedPolicy(environment);
  assert(Number.isSafeInteger(policy.epoch) && policy.epoch > 0, "policy epoch is invalid");
  const packageDocs = await packageDocuments();
  const placementRoot =
    `/v1/tenants/${encodeURIComponent(tenant)}`
    + `/placements/${encodeURIComponent(placement)}`;
  const route = async (path, init = {}, accepted = [200]) => {
    const headers = new Headers(init.headers);
    headers.set("authorization", `Bearer ${token}`);
    headers.set("accept", "application/json");
    if (init.body !== undefined) headers.set("content-type", "application/json");
    const response = await fetchImpl(`${origin}${placementRoot}${path}`, {
      ...init,
      headers,
      signal: init.signal ?? AbortSignal.timeout(90_000),
    });
    assertStatus(response, accepted, `${init.method ?? "GET"} ${path}`);
    return response;
  };

  const denied = await fetchImpl(`${origin}${placementRoot}/host/policy`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ epoch: policy.epoch, signed_envelope: policy.signedEnvelope }),
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(denied.status, 401, "managed placement admitted a missing control token");

  const policyResponse = await route("/host/policy", {
    method: "POST",
    body: JSON.stringify({ epoch: policy.epoch, signed_envelope: policy.signedEnvelope }),
  }, [200, 201]);
  const policyBody = await responseJson(policyResponse, "host policy");
  assert.equal(policyBody?.envelope_hash, policy.ref.envelope_hash);
  assert.equal(policyBody?.signer, policy.ref.signer);

  const openResponse = await route("/host/instances/open", {
    method: "POST",
    body: JSON.stringify({
      command: {
        protocol: hostProtocol,
        request_id: "production-wiring-canary:managed:open:v1",
        package_version_ref: packageDocs.version_ref,
        policy: policy.ref,
      },
      package: packageDocs,
    }),
  }, [200, 201]);
  const opened = await responseJson(openResponse, "instance open");
  assert.equal(typeof opened?.instance_ref, "string", "instance open omitted instance_ref");
  const instancePath = `/host/instances/${encodeURIComponent(opened.instance_ref)}`;
  const baselineCut = "production-wiring-canary-clean-v1";
  const checkpoint = await route(`${instancePath}/checkpoint`, {
    method: "POST",
    body: JSON.stringify({ cut_id: baselineCut }),
  });
  await responseJson(checkpoint, "baseline checkpoint");

  let live;
  let primaryError;
  let result;
  try {
    const synced = await route(`${instancePath}/files/sync`, {
      method: "POST",
      body: JSON.stringify({
        files: [{ path: "production-wiring.txt", content: "authenticated production wiring" }],
        delete_missing: true,
      }),
    });
    assert.deepEqual(await responseJson(synced, "file sync"), { synced: 1 });

    const socketUrl = new URL(`${origin}${placementRoot}${instancePath}/events/live`);
    socketUrl.protocol = "wss:";
    live = await openLiveSocket(socketUrl.href, token);
    assert.equal(live.firstMessage?.type, "runtime_events");

    const beforeResponse = await route(`${instancePath}/position`);
    const before = await responseJson(beforeResponse, "position before turn");
    assert.equal(before?.instance_ref, opened.instance_ref);

    const turnCommand = (commandId, text) => ({
      protocol: hostProtocol,
      command_id: commandId,
      run_ref: `gaugewright:production-wiring:${commandId}`,
      instance_ref: opened.instance_ref,
      package_version_ref: packageDocs.version_ref,
      policy: policy.ref,
      actor_ref: "synthetic-wiring",
      input: { text, images: [] },
      resources: [],
      provider_binding: {
        binding_id: policy.providerBindingRef,
        credential: { credential_id: policy.credentialRef },
      },
      placement_ceiling_ref: policy.placementRef,
    });
    const completedCommand = "production-wiring-canary-turn-v1";
    const turnResponse = await route("/host/turns", {
      method: "POST",
      body: JSON.stringify({
        command: turnCommand(completedCommand, "Reply with the single word wired."),
        package: packageDocs,
        image_bodies: [],
      }),
    });
    const turn = await responseJson(turnResponse, "managed turn");
    assert.equal(turn?.admitted, true);
    assert.equal(turn?.command_id, completedCommand);

    const turnStream = await route(
      `${instancePath}/turns/${encodeURIComponent(completedCommand)}/stream`,
    );
    assert.match(turnStream.headers.get("content-type") ?? "", /text\/event-stream/);
    const turnEvents = await turnStream.text();
    assert(turnEvents.length <= 1_000_000 && turnEvents.length > 0, "turn stream is empty");

    const eventStream = await route(`${instancePath}/events/stream?after=0`);
    assert.match(eventStream.headers.get("content-type") ?? "", /text\/event-stream/);
    const runtimeEvents = await eventStream.text();
    assert(runtimeEvents.includes("event: runtime"), "runtime event stream is empty");

    const afterResponse = await route(`${instancePath}/position`);
    const after = await responseJson(afterResponse, "position after turn");
    assert(after.sequence > before.sequence, "managed turn did not advance durable position");

    const exportedResponse = await route(
      `${instancePath}/fork-export?sequence=${encodeURIComponent(after.sequence)}`,
    );
    const exported = await responseJson(exportedResponse, "fork export");
    const importedResponse = await route("/host/forks/import", {
      method: "POST",
      body: JSON.stringify({
        command: {
          protocol: hostProtocol,
          request_id: "production-wiring-canary:managed:fork:v1",
          source: after,
          target_request_id: "production-wiring-canary:managed:fork-target:v1",
          package_version_ref: packageDocs.version_ref,
          policy: policy.ref,
        },
        export: exported,
        package: packageDocs,
      }),
    }, [200, 201]);
    const imported = await responseJson(importedResponse, "fork import");
    assert.equal(typeof imported?.target?.instance_ref, "string", "fork import omitted target");

    const cancelCommand = "production-wiring-canary-cancel-v1";
    const cancelableTurn = route("/host/turns", {
      method: "POST",
      body: JSON.stringify({
        command: turnCommand(cancelCommand, "Return a short bounded cancellation response."),
        package: packageDocs,
        image_bodies: [],
      }),
    });
    await new Promise((resolve) => setImmediate(resolve));
    const cancellationResponse = await route(
      `${instancePath}/turns/${encodeURIComponent(cancelCommand)}/cancel`,
      { method: "POST", body: "{}" },
      [202, 409],
    );
    const cancellation = await responseJson(cancellationResponse, "turn cancellation");
    if (cancellationResponse.status === 202) {
      assert.equal(cancellation?.status, "requested");
    } else {
      assert.match(cancellation?.error ?? "", /terminal|complete|cancel/i);
    }
    await cancelableTurn;

    result = {
      instance: opened.instance_ref,
      completedCommand,
      cancelCommand,
      fork: imported.target.instance_ref,
    };
  } catch (error) {
    primaryError = error;
  }

  const cleanupErrors = [];
  try {
    live?.close();
  } catch (error) {
    cleanupErrors.push(error);
  }
  try {
    const restored = await route(`${instancePath}/restore`, {
      method: "POST",
      body: JSON.stringify({ cut_id: baselineCut }),
    });
    await responseJson(restored, "baseline restore");
  } catch (error) {
    cleanupErrors.push(error);
  }
  try {
    const cleared = await route(`${instancePath}/files/sync`, {
      method: "POST",
      body: JSON.stringify({ files: [], delete_missing: true }),
    });
    await responseJson(cleared, "file cleanup");
  } catch (error) {
    cleanupErrors.push(error);
  }
  if (primaryError || cleanupErrors.length) {
    throw new AggregateError(
      [...(primaryError ? [primaryError] : []), ...cleanupErrors],
      "managed WhippleScript production wiring or cleanup failed",
    );
  }
  return result;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function base64UrlBytes(value) {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function p256PublicHex(jwk) {
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  assert(jwk.x && jwk.y, "private Home signer JWK has no public point");
  const x = base64UrlBytes(jwk.x);
  const y = base64UrlBytes(jwk.y);
  assert.equal(x.byteLength, 32);
  assert.equal(y.byteLength, 32);
  return `04${x.toString("hex")}${y.toString("hex")}`;
}

function governanceSigningBytes(envelopeHash, signer, keyId) {
  let value = "whipplescript-governance-envelope:v1;";
  for (const item of [envelopeHash, signer, "p256-sha256", keyId]) {
    value += `${Buffer.byteLength(item)}:${item};`;
  }
  return encoder.encode(value);
}

async function privatePolicy(signerKey, signerName, keyId) {
  const unsigned = {
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
    resources: {
      "placement:do": { principal: true, reader: [], writer: [] },
      "provider:openai": { principal: true, reader: [], writer: [] },
    },
  };
  const body = canonicalJson(unsigned);
  const envelopeHash = await sha256Hex(body);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signerKey,
    governanceSigningBytes(envelopeHash, signerName, keyId),
  );
  return {
    envelopeHash,
    text: canonicalJson({
      ...unsigned,
      attestation: {
        algorithm: "p256-sha256",
        envelope_hash: envelopeHash,
        key_id: keyId,
        signature: Buffer.from(signature).toString("hex"),
        signer: signerName,
      },
    }),
  };
}

export async function runPrivateHome(environment = process.env, fetchImpl = fetch) {
  const origin = exactOrigin(environment, "GW_SYNTHETIC_WHIP_PRIVATE_ORIGIN");
  const home = boundedId(environment, "GW_SYNTHETIC_WHIP_PRIVATE_HOME", "synthetic-wiring");
  const tenant = boundedId(environment, "GW_SYNTHETIC_WHIP_PRIVATE_TENANT", "synthetic-wiring");
  const project = boundedId(environment, "GW_SYNTHETIC_WHIP_PRIVATE_PROJECT", "synthetic-wiring");
  const command = "production-wiring-canary-private-v1";
  const epoch = 1;
  const signerName = required(environment, "GW_SYNTHETIC_WHIP_PRIVATE_GOVERNANCE_SIGNER");
  let privateJwk;
  try {
    privateJwk = JSON.parse(required(environment, "GW_SYNTHETIC_WHIP_PRIVATE_SIGNER_JWK"));
  } catch {
    assert.fail("GW_SYNTHETIC_WHIP_PRIVATE_SIGNER_JWK is not JSON");
  }
  assert.equal(typeof privateJwk.d, "string", "private Home signer JWK has no private key");
  const keyId = environment.GW_SYNTHETIC_WHIP_PRIVATE_KEY_ID?.trim()
    || p256PublicHex(privateJwk);
  const signerKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const policy = await privatePolicy(signerKey, signerName, p256PublicHex(privateJwk));
  const packageDocs = await packageDocuments();
  const outer =
    `/v1/homes/${encodeURIComponent(home)}`
    + `/tenants/${encodeURIComponent(tenant)}`
    + `/projects/${encodeURIComponent(project)}`
    + `/commands/${encodeURIComponent(command)}`
    + `/attempts/${epoch}`;

  const signedHeaders = async (innerPath, method, body = "") => {
    const now = Math.floor(Date.now() / 1000);
    const grant = {
      version: 1,
      key_id: keyId,
      governance_signer: signerName,
      home_id: home,
      tenant_id: tenant,
      project_id: project,
      work_target_basis: "whipple:cut:production-wiring-v1",
      command_id: command,
      attempt_id: `attempt:${command}:${epoch}`,
      payload_digest: `sha256:${"1".repeat(64)}`,
      epoch,
      profile: "durable_workflow",
      package_ref: packageDocs.version_ref,
      capabilities: [],
      credential_class: "private-home",
      max_spend_nanos_usd: 0,
      retention_seconds: 3600,
      callback_ref: "https://synthetic.invalid/internal/model-egress",
      request_method: method,
      request_path: innerPath,
      request_body_sha256: await sha256Hex(body),
      issued_at: now,
      expires_at: now + 300,
    };
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      signerKey,
      encoder.encode(canonicalJson(grant)),
    );
    return {
      accept: "application/json",
      ...(method === "POST" ? { "content-type": "application/json" } : {}),
      "x-gaugewright-execution-grant": Buffer.from(JSON.stringify(grant)).toString("base64url"),
      "x-gaugewright-execution-signature": Buffer.from(signature).toString("base64"),
    };
  };
  const admitted = async (innerPath, method = "GET", body = "", accepted = [200]) => {
    const response = await fetchImpl(`${origin}${outer}${innerPath}`, {
      method,
      headers: await signedHeaders(innerPath, method, body),
      ...(method === "POST" ? { body } : {}),
      signal: AbortSignal.timeout(30_000),
    });
    assertStatus(response, accepted, `${method} ${innerPath}`);
    return response;
  };

  const policyBody = JSON.stringify({ epoch, signed_envelope: policy.text });
  const unauthorized = await fetchImpl(`${origin}${outer}/host/policy`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: policyBody,
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(unauthorized.status, 401, "Private Home admitted a missing execution grant");

  const tamperedHeaders = await signedHeaders("/host/policy", "POST", policyBody);
  const tampered = await fetchImpl(`${origin}${outer}/host/policy`, {
    method: "POST",
    headers: tamperedHeaders,
    body: `${policyBody} `,
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(tampered.status, 403, "Private Home admitted a tampered request body");

  const policyResponse = await admitted("/host/policy", "POST", policyBody, [200, 201]);
  const admittedPolicy = await responseJson(policyResponse, "Private Home policy");
  assert.equal(admittedPolicy?.envelope_hash, policy.envelopeHash);
  const policyRef = {
    epoch,
    envelope_hash: policy.envelopeHash,
    signer: signerName,
    key_id: p256PublicHex(privateJwk),
  };
  const openBody = JSON.stringify({
    command: {
      protocol: hostProtocol,
      request_id: "production-wiring-canary:private:open:v1",
      package_version_ref: packageDocs.version_ref,
      policy: policyRef,
    },
    package: packageDocs,
  });
  const openResponse = await admitted("/host/instances/open", "POST", openBody, [200, 201]);
  const opened = await responseJson(openResponse, "Private Home instance open");
  assert.equal(typeof opened?.instance_ref, "string", "Private Home open omitted instance_ref");
  const positionPath = `/host/instances/${encodeURIComponent(opened.instance_ref)}/position`;
  const positionResponse = await admitted(positionPath);
  const position = await responseJson(positionResponse, "Private Home position");
  assert.equal(position?.instance_ref, opened.instance_ref);
  return { instance: opened.instance_ref, command };
}

const runners = {
  "managed-host-lifecycle": runManagedHost,
  "private-home-forwarding": runPrivateHome,
};

async function main() {
  const id = process.argv[2];
  const runner = runners[id];
  assert(runner, `unknown production wiring suite ${id ?? "<missing>"}`);
  await runner();
  console.log(`${id} authenticated production wiring passed`);
}

const invoked = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) await main();
