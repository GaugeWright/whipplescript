#!/usr/bin/env node

import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
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

function managedPolicy(environment, key = "GW_SYNTHETIC_WHIP_SIGNED_POLICY") {
  const signedEnvelope = required(environment, key);
  let envelope;
  try {
    envelope = JSON.parse(signedEnvelope);
  } catch {
    assert.fail(`${key} is not JSON`);
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
    provider,
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
    const forkPath = `/host/instances/${encodeURIComponent(imported.target.instance_ref)}`;
    const discardedResponse = await route(`${forkPath}/discard`, {
      method: "POST",
      body: JSON.stringify({
        command: {
          protocol: hostProtocol,
          request_id: "production-wiring-canary:managed:discard:v1",
          instance_ref: imported.target.instance_ref,
          policy: policy.ref,
        },
      }),
    });
    const discarded = await responseJson(discardedResponse, "fork discard");
    assert.equal(discarded?.instance_ref, imported.target.instance_ref);
    assert.equal(discarded?.discarded_at?.instance_ref, imported.target.instance_ref);

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

/** Capture one exact provider body while the closed synthetic provider holds
 * its response bytes, then prove the privileged view disappears on settlement.
 * The policy must name only that synthetic provider; the runner never sends a
 * customer turn or prints the captured body. */
export async function runLiveModelContext(environment = process.env, fetchImpl = fetch) {
  const origin = exactOrigin(environment, "GW_SYNTHETIC_WHIP_MANAGED_ORIGIN");
  const providerOrigin = exactOrigin(environment, "GW_SYNTHETIC_WHIP_RAW_CONTEXT_PROVIDER_ORIGIN");
  const token = required(environment, "GW_SYNTHETIC_WHIP_CONTROL_TOKEN");
  const publicToken = required(environment, "GW_SYNTHETIC_WHIP_PUBLIC_TOKEN");
  assert.notEqual(publicToken, token, "public and control credentials must differ");
  const tenant = boundedId(environment, "GW_SYNTHETIC_WHIP_TENANT", "synthetic-wiring");
  const placement = boundedId(
    environment,
    "GW_SYNTHETIC_WHIP_RAW_CONTEXT_PLACEMENT",
    "production-raw-context-canary-v1",
  );
  const policy = managedPolicy(environment, "GW_SYNTHETIC_WHIP_RAW_CONTEXT_SIGNED_POLICY");
  const policyDocument = JSON.parse(policy.signedEnvelope);
  assert.deepEqual(
    Object.keys(policyDocument.provider_bindings),
    [policy.providerBindingRef],
    "Raw context canary policy must have only one provider binding",
  );
  assert.deepEqual(
    Object.keys(policyDocument.placements),
    [policy.placementRef],
    "Raw context canary policy must have only one placement",
  );
  assert.deepEqual(
    policyDocument.placements[policy.placementRef]?.provider_bindings,
    [policy.providerBindingRef],
    "Raw context canary placement must bind only the synthetic provider",
  );
  assert.equal(policy.provider.provider, "openai", "Raw context canary policy must use OpenAI wire");
  assert.equal(policy.provider.model, "gaugewright-canary-model-v1");
  assert.equal(
    policy.provider.base_url,
    `${providerOrigin}/_canary/openai`,
    "Raw context canary policy has a non-synthetic base_url",
  );
  const packageDocs = await packageDocuments();
  // Reuse one synthetic instance so the scheduled lane does not accumulate
  // Durable Objects. Each run needs a fresh cut and turn identity, or its
  // position ledger collides with an earlier run. The v1 instance retained an
  // unfinished effect from the pre-release canary and cannot be checkpointed.
  const runId = crypto.randomUUID().replaceAll("-", "");
  const placementRoot = `/v1/tenants/${encodeURIComponent(tenant)}`
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
  const policyResponse = await route("/host/policy", {
    method: "POST",
    body: JSON.stringify({ epoch: policy.epoch, signed_envelope: policy.signedEnvelope }),
  }, [200, 201]);
  const installed = await responseJson(policyResponse, "Raw context policy");
  assert.equal(installed?.envelope_hash, policy.ref.envelope_hash);
  const opened = await responseJson(await route("/host/instances/open", {
    method: "POST",
    body: JSON.stringify({
      command: {
        protocol: hostProtocol,
        request_id: "production-wiring-canary:raw-context:open:v2",
        package_version_ref: packageDocs.version_ref,
        policy: policy.ref,
      },
      package: packageDocs,
    }),
  }, [200, 201]), "Raw context instance open");
  assert.equal(typeof opened?.instance_ref, "string");
  const instancePath = `/host/instances/${encodeURIComponent(opened.instance_ref)}`;
  const baseline = `production-wiring-canary-raw-context-clean-${runId}`;
  await responseJson(await route(`${instancePath}/checkpoint`, {
    method: "POST", body: JSON.stringify({ cut_id: baseline }),
  }), "Raw context baseline");

  const commandId = `production-wiring-canary-raw-context-turn-${runId}`;
  const contextPath = `${instancePath}/turns/${encodeURIComponent(commandId)}/model-context`;
  let turnPromise;
  let cancelRequested = false;
  let primaryError;
  let result;
  try {
    const marker = "gaugewright-raw-context-canary-hold-v1";
    turnPromise = route("/host/turns", {
      method: "POST",
      body: JSON.stringify({
        command: {
          protocol: hostProtocol,
          command_id: commandId,
          run_ref: `gaugewright:production-wiring:${commandId}`,
          instance_ref: opened.instance_ref,
          package_version_ref: packageDocs.version_ref,
          policy: policy.ref,
          actor_ref: "synthetic-wiring",
          input: { text: marker, images: [] },
          resources: [],
          provider_binding: {
            binding_id: policy.providerBindingRef,
            credential: { credential_id: policy.credentialRef },
          },
          placement_ceiling_ref: policy.placementRef,
        },
        package: packageDocs,
        image_bodies: [],
      }),
    });
    // The model call may finish with a cancellation status. Observe its
    // settlement without leaving an unhandled rejection during the live poll.
    let settled = false;
    void turnPromise.then(() => { settled = true; }, () => { settled = true; });
    const deadline = Date.now() + 45_000;
    let capture;
    while (Date.now() < deadline) {
      const response = await route(contextPath, {}, [200, 404]);
      if (response.status === 200) {
        assert.equal(response.headers.get("cache-control"), "no-store");
        capture = await responseJson(response, "live model context");
        break;
      }
      if (settled) break;
      await delay(100);
    }
    assert(capture, "the synthetic provider never exposed an in-flight model request");
    assert.equal(capture.incomplete, false);
    assert(
      capture.calls?.some((call) => JSON.stringify(call.body).includes(marker)),
      "the live view omitted the exact synthetic provider body",
    );
    for (const authorization of [undefined, `Bearer ${publicToken}`]) {
      const headers = authorization ? { authorization } : {};
      const denied = await fetchImpl(`${origin}${placementRoot}${contextPath}`, {
        headers, signal: AbortSignal.timeout(30_000),
      });
      assert.equal(denied.status, 401, "non-control identity read live model context");
    }
    const cancellation = await route(`${instancePath}/turns/${encodeURIComponent(commandId)}/cancel`, {
      method: "POST", body: "{}",
    }, [202, 409]);
    cancelRequested = true;
    await responseJson(cancellation, "Raw context cancellation");
    await turnPromise.catch(() => null);
    const erased = await route(contextPath, {}, [404]);
    assert.equal(erased.headers.get("cache-control"), "no-store");
    result = { instance: opened.instance_ref, command: commandId };
  } catch (error) {
    primaryError = error;
  }

  const cleanupErrors = [];
  if (turnPromise) {
    if (!cancelRequested) {
      try {
        await route(`${instancePath}/turns/${encodeURIComponent(commandId)}/cancel`, {
          method: "POST", body: "{}",
        }, [202, 409]);
      } catch (error) { cleanupErrors.push(error); }
    }
    await turnPromise.catch(() => null);
  }
  try {
    await route(`${instancePath}/restore`, {
      method: "POST", body: JSON.stringify({ cut_id: baseline }),
    });
  } catch (error) { cleanupErrors.push(error); }
  try {
    await route(`${instancePath}/files/sync`, {
      method: "POST", body: JSON.stringify({ files: [], delete_missing: true }),
    });
  } catch (error) { cleanupErrors.push(error); }
  if (primaryError || cleanupErrors.length) {
    throw new AggregateError(
      [...(primaryError ? [primaryError] : []), ...cleanupErrors],
      "live model context production canary or cleanup failed",
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

// The norm-ledger suite: the six `/host/norm/*` doors of one dedicated
// synthetic ledger placement, over the same managed origin and control token
// as `managed-host-lifecycle`.
//
// It signs nothing. A norm event's identity commits to its signature as well
// as its statement (`SignedNormEvent::tracker_event`), and P-256 ECDSA is
// randomized, so a runner that signed at run time would mint a new event on
// every run: a new genesis, which the ledger refuses, or a new record, which
// grows customer-shaped history forever. An exact retry is the same signed
// envelope appended again (norm-plane-tracker V0 audit, NP-01). So the one
// signed act it presents is fixed in `GW_SYNTHETIC_NORM_SIGNED_ACT`, as the
// ledger's own export carries it, and the observation it republishes is the one
// the host retained. Both are produced outside this runner by the Rust signer
// that provisions the synthetic ledger; the deployed verifier re-judges them
// on every run, and `norm_ledger_canary_*` in `src/norm_commands.rs` proves
// that every request below decodes at the real door and that re-appending an
// act a ledger already holds is the same receipt even after the ledger moved.
//
// Nothing here erases, restores or rolls back. Norm evidence is append-only;
// the suite's only cleanup is that everything it sends is an exact retry of
// a stable identity, so after the first run it adds nothing.
//
// The suite is two journeys (DR-0140, after DR-0139). `norm-ledger` answers
// the ledger's doors and runs now. `runNormEvidence` answers the evidence
// doors, which run checks against cuts a Home supplies to its hosted peer; no
// production route supplies one until FB-6, so that journey is kept, tested,
// and not dispatched.
export const NORM_LEDGER_ROUTES = ["commands", "provision"];
export const NORM_EVIDENCE_ROUTES = ["publications", "enqueues", "impacts", "promotions"];
const normCommandProtocol = "whipplescript.norm.commands/v1";
const normImpactProtocol = "whipplescript.norm.impact/v1";
const normEnqueueProtocol = "whipplescript.norm.enqueue/v1";
const normPublicationProtocol = "whipplescript.norm.publication/v1";
const normPromotionProtocol = "whipplescript.norm.promotion/v1";
// Stable invocation identities: a re-run replays these, never mints another.
export const NORM_LEDGER_PROMOTION = "production-norm-ledger-canary:promotion:v1";
const normLedgerObservedAt = "2026-09-28T00:00:00Z";
const normLedgerUnboundPublisher = "production-norm-ledger-canary-unbound";
// The synthetic ledger holds its provisioned history, the canary's one act and
// one observation. A history past this means something is minting per run.
export const NORM_LEDGER_HISTORY_LIMIT = 256;

function jsonEnvironment(environment, name) {
  const text = required(environment, name);
  assert(text.length <= 65_536, `${name} is oversized`);
  try {
    return JSON.parse(text);
  } catch {
    assert.fail(`${name} is not JSON`);
  }
}

function boundedToken(value, label) {
  assert.equal(typeof value, "string", `${label} is required`);
  assert.match(value, /^[\x21-\x7e]{1,256}$/, `${label} is invalid`);
  return value;
}

function normActor(value, label) {
  assert(value && typeof value === "object", `${label} is required`);
  return {
    principal: boundedToken(value.principal, `${label}.principal`),
    algorithm: boundedToken(value.algorithm, `${label}.algorithm`),
    key_id: boundedToken(value.key_id, `${label}.key_id`),
  };
}

function normSignedAct(environment) {
  const act = jsonEnvironment(environment, "GW_SYNTHETIC_NORM_SIGNED_ACT");
  assert.equal(act?.statement?.protocol, "whipplescript.norm/v1", "signed act has no norm statement");
  normActor(act.statement.actor, "signed act actor");
  boundedToken(act.statement.nonce, "signed act nonce");
  assert.equal(typeof act.signature, "string", "signed act has no signature");
  assert(act.signature.length > 2, "signed act signature is empty");
  return act;
}

function normWorkspace(environment) {
  const value = jsonEnvironment(environment, "GW_SYNTHETIC_NORM_WORKSPACE");
  const ids = {};
  for (const field of ["instance", "run", "requirement", "cut", "effect", "capability"]) {
    ids[field] = boundedToken(value?.[field], `GW_SYNTHETIC_NORM_WORKSPACE.${field}`);
  }
  assert.match(
    value.vocabulary ?? "",
    /^[^@\s]{1,128}@[^@\s]{1,64}$/,
    "GW_SYNTHETIC_NORM_WORKSPACE.vocabulary must be name@version",
  );
  const tokens = value.promotion?.tokens ?? [];
  assert(Array.isArray(tokens) && tokens.length <= 16, "promotion tokens are invalid");
  return {
    ...ids,
    vocabulary: value.vocabulary,
    publisher: normActor(value.publisher, "GW_SYNTHETIC_NORM_WORKSPACE.publisher"),
    impact: {
      before_cut: boundedToken(value.impact?.before_cut, "impact.before_cut"),
      after_cut: boundedToken(value.impact?.after_cut, "impact.after_cut"),
    },
    promotion: {
      stream: boundedToken(value.promotion?.stream, "promotion.stream"),
      tokens: tokens.map((token, index) => boundedToken(token, `promotion.tokens[${index}]`)),
    },
  };
}

/// The ledger doors' request bodies. Pure; `act` is forwarded verbatim.
export function normLedgerCommandRequests(act) {
  const commands = (command) => ({ protocol: normCommandProtocol, command });
  return {
    provision: {},
    export: commands({ kind: "export" }),
    append: commands({ kind: "append", event: act }),
    // Each is refused before anything is written, and says why it must be.
    refused: {
      // A restoration is the deployment's, never the request's (NC-01).
      provision: { checkpoint: { ledger: "0".repeat(64), authority_head: "0".repeat(64) } },
      // A signature the deployment's binding cannot verify.
      append: commands({ kind: "append", event: act && { ...act, signature: "00" } }),
      // Host trust supplied by a request.
      commands: { ...commands({ kind: "export" }), bindings: [] },
    },
  };
}

/// The evidence doors' request bodies. Pure; `retained` is forwarded verbatim.
export function normEvidenceRequests(workspace, retained = null) {
  const publication = (command) => ({ protocol: normPublicationProtocol, command });
  const enqueue = (publisher) => ({
    protocol: normEnqueueProtocol,
    command: {
      instance: workspace.instance,
      requirement: workspace.requirement,
      cut: workspace.cut,
      effect: workspace.effect,
      capability: workspace.capability,
      publisher,
    },
  });
  const impact = {
    protocol: normImpactProtocol,
    command: { before_cut: workspace.impact.before_cut, after_cut: workspace.impact.after_cut },
  };
  const promotion = {
    protocol: normPromotionProtocol,
    command: {
      stream: workspace.promotion.stream,
      promotion: NORM_LEDGER_PROMOTION,
      tokens: workspace.promotion.tokens,
    },
  };
  return {
    impact,
    enqueue: enqueue(workspace.publisher.principal),
    prepare: publication({
      kind: "prepare",
      instance: workspace.instance,
      run: workspace.run,
      vocabulary: workspace.vocabulary,
      actor: workspace.publisher,
      created_at: normLedgerObservedAt,
    }),
    publish: publication({
      kind: "publish", instance: workspace.instance, run: workspace.run, event: retained,
    }),
    promotion,
    refused: {
      // Planning premises supplied by a request.
      impact: { ...impact, deployment: {} },
      // A publisher the deployment binds no key for.
      enqueue: enqueue(normLedgerUnboundPublisher),
      // A signature that is not even an encoding, which the hosted
      // publication test pins as refused for its signature.
      publish: publication({
        kind: "publish", instance: workspace.instance, run: workspace.run,
        event: retained && { ...retained, signature: "invalid" },
      }),
      promotion: { ...promotion, deployment: {} },
    },
  };
}

/// Every request body the suite sends, keyed by what it proves. Pure, so the
/// vector `norm-ledger-canary-requests.json` can pin it and the Rust doors can
/// decode exactly this: `norm_ledger_canary_requests_decode_at_every_hosted_door`.
/// `act` and `retained` are forwarded verbatim; the runner never re-signs.
export function normLedgerRequests(workspace, act, retained = null) {
  const ledger = normLedgerCommandRequests(act);
  const evidence = normEvidenceRequests(workspace, retained);
  return {
    provision: ledger.provision,
    export: ledger.export,
    append: ledger.append,
    impact: evidence.impact,
    enqueue: evidence.enqueue,
    prepare: evidence.prepare,
    publish: evidence.publish,
    promotion: evidence.promotion,
    refused: {
      provision: ledger.refused.provision,
      append: ledger.refused.append,
      commands: ledger.refused.commands,
      impact: evidence.refused.impact,
      enqueue: evidence.refused.enqueue,
      publish: evidence.refused.publish,
      promotion: evidence.refused.promotion,
    },
  };
}

function eventIds(exported, label) {
  const events = exported?.result?.events;
  assert(Array.isArray(events), `${label} returned no history`);
  assert(
    events.length <= NORM_LEDGER_HISTORY_LIMIT,
    `${label} holds ${events.length} events; the synthetic ledger is bounded at `
      + `${NORM_LEDGER_HISTORY_LIMIT}, so something is minting new acts per run`,
  );
  return events.map((event) => event.event_id);
}

function withoutTimeBasis(body) {
  return JSON.parse(JSON.stringify(body), (key, value) =>
    key === "time_basis" ? "<per-query>" : value);
}

/// The dedicated placement's norm doors, with the calls every journey makes.
function normSession(environment, fetchImpl) {
  const origin = exactOrigin(environment, "GW_SYNTHETIC_WHIP_MANAGED_ORIGIN");
  const token = required(environment, "GW_SYNTHETIC_WHIP_CONTROL_TOKEN");
  const tenant = boundedId(environment, "GW_SYNTHETIC_WHIP_TENANT", "synthetic-wiring");
  const placement = boundedId(
    environment,
    "GW_SYNTHETIC_NORM_PLACEMENT",
    "production-norm-ledger-canary-v1",
  );
  const root =
    `/v1/tenants/${encodeURIComponent(tenant)}`
    + `/placements/${encodeURIComponent(placement)}/host/norm`;
  const post = async (operation, body, authorization = `Bearer ${token}`) => fetchImpl(
    `${origin}${root}/${operation}`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        ...(authorization ? { authorization } : {}),
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(90_000),
    },
  );
  const answered = async (operation, body, label) => {
    const response = await post(operation, body);
    assertStatus(response, [200], label);
    return responseJson(response, label);
  };
  const refused = async (operation, body, label, pattern) => {
    const response = await post(operation, body);
    const text = await response.text();
    assert.equal(response.status, 400, `${label} was not refused (${response.status})`);
    if (pattern) assert.match(text, pattern, `${label} was refused for another reason`);
  };
  // Every door refuses a missing and a wrong control token at the edge. The
  // body is an empty object, which no door but provision decodes and which
  // provision answers idempotently, so even a broken edge turns no probe into
  // a new effect.
  const deniesStrangers = async (routes) => {
    for (const operation of routes) {
      for (const authorization of [null, `Bearer ${token}.invalid`]) {
        const denied = await post(operation, {}, authorization);
        await denied.text();
        assert.equal(
          denied.status,
          401,
          `${operation} admitted ${authorization ? "a wrong" : "a missing"} control token`,
        );
      }
    }
  };
  return { answered, refused, deniesStrangers };
}

export async function runNormLedger(environment = process.env, fetchImpl = fetch) {
  const act = normSignedAct(environment);
  const { answered, refused, deniesStrangers } = normSession(environment, fetchImpl);
  await deniesStrangers(NORM_LEDGER_ROUTES);
  const requests = normLedgerCommandRequests(act);

  // Provision pins only the deployment's configured checkpoint for this object;
  // re-pinning the same one is idempotent, and a request cannot choose it.
  const provisioned = await answered("provision", requests.provision, "norm provision");
  assert.match(provisioned?.checkpoint?.ledger ?? "", /^[0-9a-f]{64}$/);
  assert.match(provisioned?.checkpoint?.authority_head ?? "", /^[0-9a-f]{64}$/);
  await refused("provision", requests.refused.provision, "request-selected provision");

  // Commands: read the history, append the one stable signed act, append it
  // again, and prove that the retry is the same receipt and added nothing.
  const before = await answered("commands", requests.export, "norm export");
  assert.equal(before?.result?.kind, "exported");
  assert.equal(before.result.checkpoint?.ledger, provisioned.checkpoint.ledger);
  const beforeIds = eventIds(before, "norm export");
  const appended = await answered("commands", requests.append, "norm append");
  assert.equal(appended?.result?.kind, "appended");
  assert.match(appended.result.event_id ?? "", /^[0-9a-f]{64}$/);
  const retried = await answered("commands", requests.append, "norm append retry");
  assert.deepEqual(retried, appended, "an exact retry of the signed act is a different receipt");
  await refused("commands", requests.refused.append, "unverifiable signed act");
  await refused("commands", requests.refused.commands, "request-supplied norm trust", /unknown field/);
  const after = await answered("commands", requests.export, "norm export after append");
  const afterIds = eventIds(after, "norm export after append");
  assert(afterIds.includes(appended.result.event_id), "the appended act is not in the history");
  assert.equal(
    afterIds.length,
    beforeIds.length + (beforeIds.includes(appended.result.event_id) ? 0 : 1),
    "appending one stable act changed the history by more than that act",
  );

  // Append-only: nothing any step did removed or replaced history.
  const final = await answered("commands", requests.export, "final norm export");
  const finalIds = eventIds(final, "final norm export");
  for (const id of afterIds) {
    assert(finalIds.includes(id), `history lost ${id}; norm evidence is append-only`);
  }
  assert.equal(final.result.checkpoint?.ledger, provisioned.checkpoint.ledger);

  return {
    ledger: provisioned.checkpoint.ledger,
    act: appended.result.event_id,
    history: finalIds.length,
  };
}

/// The evidence doors, against the checks a Home's hosted peer runs. Not
/// dispatched until FB-6 lets a Home supply the peer with cuts (DR-0139).
export async function runNormEvidence(environment = process.env, fetchImpl = fetch) {
  const workspace = normWorkspace(environment);
  const { answered, refused, deniesStrangers } = normSession(environment, fetchImpl);
  await deniesStrangers(NORM_EVIDENCE_ROUTES);
  const requests = normEvidenceRequests(workspace);
  const exportRequest = normLedgerCommandRequests(null).export;
  const start = await answered("commands", exportRequest, "norm export");
  const startIds = eventIds(start, "norm export");

  // Impacts: a read-only query under the deployment's installed planning.
  const planned = await answered("impacts", requests.impact, "norm impact");
  assert.equal(planned?.protocol, normImpactProtocol);
  assert.match(planned?.result?.plan?.time_basis ?? "", /^hosted-impact\/\d+\/[0-9a-f-]+$/);
  const replanned = await answered("impacts", requests.impact, "norm impact repeat");
  assert.deepEqual(
    withoutTimeBasis(replanned),
    withoutTimeBasis(planned),
    "the same impact query planned differently",
  );
  await refused("impacts", requests.refused.impact, "request-supplied planning", /unknown field/);
  const unmoved = await answered("commands", exportRequest, "norm export after impact");
  assert.deepEqual(unmoved.result.frontier, start.result.frontier, "an impact query moved the ledger");

  // Enqueues: one stable effect identity. The first run admits it; every run
  // after is the same acknowledgment.
  const enqueued = await answered("enqueues", requests.enqueue, "norm enqueue");
  assert.equal(enqueued?.protocol, normEnqueueProtocol);
  assert.equal(enqueued?.result?.effect_id, workspace.effect);
  const reenqueued = await answered("enqueues", requests.enqueue, "norm enqueue retry");
  assert.deepEqual(reenqueued, enqueued, "an enqueue retry was not the same acknowledgment");
  await refused("enqueues", requests.refused.enqueue, "unbound publisher", /deployment binding/);

  // Publications: the settled synthetic run's observation was published once,
  // externally signed, when the peer was provisioned. The host retains it,
  // and republishing exactly it re-verifies the signature against the
  // deployment's binding and the recovered execution, and is the same receipt.
  const prepared = await answered("publications", requests.prepare, "norm publication prepare");
  assert.equal(prepared?.protocol, normPublicationProtocol);
  assert.equal(
    prepared?.result?.kind,
    "retained",
    "the synthetic run's observation has never been published: provisioning signs and "
      + "publishes it once, and this canary only republishes what the host retains",
  );
  const retained = prepared.result.event;
  assert.equal(retained?.statement?.actor?.principal, workspace.publisher.principal);
  const published = normEvidenceRequests(workspace, retained);
  const receipt = await answered("publications", published.publish, "norm publication");
  assert.match(receipt?.result?.event_id ?? "", /^[0-9a-f]{64}$/);
  const republished = await answered("publications", published.publish, "norm publication retry");
  assert.deepEqual(republished, receipt, "republishing the retained observation was a new receipt");
  await refused("publications", published.refused.publish, "unverifiable observation", /signature/i);

  // Promotions: one stable promotion of the synthetic stream, which on a peer
  // moves only a line the peer holds (DR-0139). Promoted once, every later run
  // recovers the same receipt.
  const promoted = await answered("promotions", requests.promotion, "norm promotion");
  assert.equal(promoted?.protocol, normPromotionProtocol);
  assert.equal(
    promoted?.result?.promoted,
    workspace.promotion.stream,
    `the synthetic promotion was not promoted: ${JSON.stringify(promoted?.result).slice(0, 512)}`,
  );
  assert.equal(promoted.result.into, "main");
  const repromoted = await answered("promotions", requests.promotion, "norm promotion retry");
  assert.deepEqual(repromoted, promoted, "a promotion retry was not the recovered receipt");
  await refused("promotions", requests.refused.promotion, "request-supplied planning", /unknown field/);

  const final = await answered("commands", exportRequest, "final norm export");
  const finalIds = eventIds(final, "final norm export");
  for (const id of startIds) {
    assert(finalIds.includes(id), `history lost ${id}; norm evidence is append-only`);
  }
  return {
    effect: enqueued.result.effect_id,
    observation: receipt.result.event_id,
    promoted: promoted.result.promoted,
    history: finalIds.length,
  };
}

/// The journeys this runner performs, keyed by the `#marker` an inventory
/// runner names. A marker is a journey, not a suite: `placement-forwarding` is
/// proved by the managed-host journey, which forwards through the placement
/// root, so it names `#managed-host-lifecycle` and has no key of its own.
export const runners = {
  "managed-host-lifecycle": runManagedHost,
  "live-model-context": runLiveModelContext,
  "private-home-forwarding": runPrivateHome,
  "norm-ledger": runNormLedger,
};

async function main() {
  const marker = process.argv[2];
  const runner = Object.hasOwn(runners, marker ?? "") ? runners[marker] : undefined;
  assert(runner, `unknown production wiring journey ${marker ?? "<missing>"}`);
  await runner();
  console.log(`${marker} authenticated production wiring passed`);
}

const invoked = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) await main();
