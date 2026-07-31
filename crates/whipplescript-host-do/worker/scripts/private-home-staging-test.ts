import assert from "node:assert/strict";
import fs from "node:fs";
import {
  canonicalJson,
  sha256Hex,
  type DurableWorkflowGrant,
} from "../src/private-home-protocol.ts";

const endpoint =
  process.env.WHIP_PRIVATE_HOME_STAGING_URL ??
  "https://whipplescript-private-home-runtime-staging.jack-168.workers.dev";
const privateJwkText = process.env.MACHINE_STAGING_SIGNER_JWK;
assert(privateJwkText, "MACHINE_STAGING_SIGNER_JWK is required");
const privateJwk = JSON.parse(privateJwkText) as JsonWebKey;

const signer = await crypto.subtle.importKey(
  "jwk",
  privateJwk,
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign"],
);

const textEncoder = new TextEncoder();
const mode = process.argv[2] ?? "admission";
const statePath = process.argv[3];
const homeId = "home:synthetic-staging";
const tenantId = "tenant:synthetic-staging";
const projectId = "project:synthetic-staging";
const governanceSigner = "staging-home-authority";
const admissionKeyId = "staging-home-key:1";

function base64UrlBytes(value: string): Uint8Array {
  return Uint8Array.from(
    Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64"),
  );
}

function governanceP256Hex(jwk: JsonWebKey): string {
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  assert(jwk.x && jwk.y, "staging JWK must contain a public point");
  const x = base64UrlBytes(jwk.x);
  const y = base64UrlBytes(jwk.y);
  assert.equal(x.byteLength, 32);
  assert.equal(y.byteLength, 32);
  return `04${Buffer.from(x).toString("hex")}${Buffer.from(y).toString("hex")}`;
}

function hex(value: ArrayBuffer): string {
  return Buffer.from(value).toString("hex");
}

function signingBytes(
  envelopeHash: string,
  authority: string,
  algorithm: string,
  keyId: string,
): Uint8Array {
  let value = "whipplescript-governance-envelope:v1;";
  for (const item of [envelopeHash, authority, algorithm, keyId]) {
    value += `${Buffer.byteLength(item)}:${item};`;
  }
  return textEncoder.encode(value);
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
    tell assistant "Answer without tools."
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
    max_steps: 8,
  });
  const systemPrompt = "Be helpful.";
  const version = await sha256Hex(
    textEncoder.encode(JSON.stringify({ manifest, source, system_prompt: systemPrompt })),
  );
  return {
    manifest,
    source,
    system_prompt: systemPrompt,
    version_ref: `whip:agent-package:${version}`,
  };
}

async function signedPolicy() {
  const publicKeyHex = governanceP256Hex(privateJwk);
  const unsigned = {
    bindings: {
      do: "placement:do",
      model: "provider:openai",
    },
    declassifications: [],
    delegations: [],
    endorsements: [],
    parties: {},
    placements: {
      do: {
        kind: "durable_object",
        provider_bindings: ["model"],
      },
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
  const canonical = canonicalJson(unsigned);
  const envelopeHash = await sha256Hex(textEncoder.encode(canonical));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signer,
    signingBytes(envelopeHash, governanceSigner, "p256-sha256", publicKeyHex),
  );
  return {
    envelopeHash,
    publicKeyHex,
    text: canonicalJson({
      ...unsigned,
      attestation: {
        algorithm: "p256-sha256",
        envelope_hash: envelopeHash,
        key_id: publicKeyHex,
        signature: hex(signature),
        signer: governanceSigner,
      },
    }),
  };
}

function outerPath(commandId: string, epoch: number, innerPath: string): string {
  return (
    `/v1/homes/${encodeURIComponent(homeId)}` +
    `/tenants/${encodeURIComponent(tenantId)}` +
    `/projects/${encodeURIComponent(projectId)}` +
    `/commands/${encodeURIComponent(commandId)}` +
    `/attempts/${epoch}${innerPath}`
  );
}

async function signedHeaders(
  commandId: string,
  packageRef: string,
  epoch: number,
  requestPath: string,
  requestBody: string,
): Promise<Record<string, string>> {
  const now = Math.floor(Date.now() / 1000);
  const grant: DurableWorkflowGrant = {
    version: 1,
    key_id: admissionKeyId,
    governance_signer: governanceSigner,
    home_id: homeId,
    tenant_id: tenantId,
    project_id: projectId,
    work_target_basis: "whipple:cut:synthetic-v1",
    command_id: commandId,
    attempt_id: `attempt:${commandId}:${epoch}`,
    payload_digest: `sha256:${"1".repeat(64)}`,
    epoch,
    profile: "durable_workflow",
    package_ref: packageRef,
    capabilities: ["chat", "http_effect"],
    credential_class: "private-home",
    max_spend_nanos_usd: 0,
    retention_seconds: 3600,
    callback_ref: "https://staging-home.invalid/internal/model-egress",
    request_method: requestBody ? "POST" : "GET",
    request_path: requestPath,
    request_body_sha256: await sha256Hex(textEncoder.encode(requestBody)),
    issued_at: now,
    expires_at: now + 300,
  };
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signer,
    textEncoder.encode(canonicalJson(grant)),
  );
  return {
    ...(requestBody ? { "content-type": "application/json" } : {}),
    "x-gaugewright-execution-grant": Buffer.from(
      JSON.stringify(grant),
    ).toString("base64url"),
    "x-gaugewright-execution-signature":
      Buffer.from(signature).toString("base64"),
  };
}

async function admittedFetch(
  commandId: string,
  packageRef: string,
  epoch: number,
  innerPath: string,
  body = "",
): Promise<Response> {
  return fetch(`${endpoint}${outerPath(commandId, epoch, innerPath)}`, {
    method: body ? "POST" : "GET",
    headers: await signedHeaders(commandId, packageRef, epoch, innerPath, body),
    ...(body ? { body } : {}),
  });
}

async function admissionProof(): Promise<void> {
  const commandId = "command:durable-admission:governance-v1";
  const packageRef = "sha256:synthetic-package";
  const innerPath = "/host/policy";
  const body = JSON.stringify({ epoch: 1, signed_envelope: "intentionally-invalid" });
  const route = outerPath(commandId, 1, innerPath);

  const health = await fetch(`${endpoint}/healthz`);
  assert.equal(health.status, 200);
  assert.equal(
    (await health.json() as { surface?: string }).surface,
    "private-durable-workflow",
  );

  const unauthorized = await fetch(`${endpoint}${route}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  assert.equal(unauthorized.status, 401);

  const admitted = await admittedFetch(
    commandId,
    packageRef,
    1,
    innerPath,
    body,
  );
  const admittedBody = await admitted.text();
  assert.equal(
    admitted.status,
    403,
    `signed invalid policy was not rejected by the isolated runtime: ${admittedBody}`,
  );
  assert.match(
    admittedBody,
    /policy rejected/,
    "signed admission did not reach Whipple's policy verifier",
  );

  const tampered = await fetch(`${endpoint}${route}`, {
    method: "POST",
    headers: await signedHeaders(
      commandId,
      packageRef,
      1,
      "/host/turns",
      body,
    ),
    body,
  });
  assert.equal(tampered.status, 403);
  console.log("private Durable workflow staging admission passed");
}

interface RestartState {
  command_id: string;
  package_ref: string;
  instance_ref: string;
  position: unknown;
  policy: {
    epoch: number;
    envelope_hash: string;
    signer: string;
    key_id: string;
    signed_envelope: string;
  };
}

async function openProof(): Promise<void> {
  assert(statePath, "open requires a state-file path");
  const suffix = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const commandId = `command:durable-restart:${suffix}`;
  const packageDocs = await packageDocuments();
  const policy = await signedPolicy();
  const policyBody = JSON.stringify({
    epoch: 1,
    signed_envelope: policy.text,
  });
  const admittedPolicy = await admittedFetch(
    commandId,
    packageDocs.version_ref,
    1,
    "/host/policy",
    policyBody,
  );
  assert(
    admittedPolicy.status === 200 || admittedPolicy.status === 201,
    `valid Home policy was rejected: ${await admittedPolicy.clone().text()}`,
  );
  const policyRef = await admittedPolicy.json() as {
    epoch: number;
    envelope_hash: string;
    signer: string;
    key_id: string;
  };
  assert.deepEqual(policyRef, {
    epoch: 1,
    envelope_hash: policy.envelopeHash,
    signer: governanceSigner,
    key_id: policy.publicKeyHex,
  });

  const openCommand = {
    protocol: "whipplescript.host.v1",
    request_id: `staging:${commandId}:open`,
    package_version_ref: packageDocs.version_ref,
    policy: policyRef,
  };
  const openBody = JSON.stringify({
    command: openCommand,
    package: {
      manifest: packageDocs.manifest,
      source: packageDocs.source,
      system_prompt: packageDocs.system_prompt,
    },
  });
  const opened = await admittedFetch(
    commandId,
    packageDocs.version_ref,
    1,
    "/host/instances/open",
    openBody,
  );
  assert(
    opened.status === 200 || opened.status === 201,
    `valid instance open failed: ${await opened.clone().text()}`,
  );
  const openedBody = await opened.json() as { instance_ref?: string };
  assert(openedBody.instance_ref, "instance open omitted instance_ref");
  const positionPath =
    `/host/instances/${encodeURIComponent(openedBody.instance_ref)}/position`;
  const positionResponse = await admittedFetch(
    commandId,
    packageDocs.version_ref,
    1,
    positionPath,
  );
  assert.equal(
    positionResponse.status,
    200,
    `opened instance position failed: ${await positionResponse.clone().text()}`,
  );
  const position = await positionResponse.json();
  const state: RestartState = {
    command_id: commandId,
    package_ref: packageDocs.version_ref,
    instance_ref: openedBody.instance_ref,
    position,
    policy: {
      epoch: 1,
      envelope_hash: policy.envelopeHash,
      signer: governanceSigner,
      key_id: policy.publicKeyHex,
      signed_envelope: policy.text,
    },
  };
  fs.writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
  console.log(`private Durable workflow instance opened: ${state.instance_ref}`);
}

async function resumeProof(): Promise<void> {
  assert(statePath, "resume requires a state-file path");
  const state = JSON.parse(fs.readFileSync(statePath, "utf8")) as RestartState;
  const policyBody = JSON.stringify({
    epoch: state.policy.epoch,
    signed_envelope: state.policy.signed_envelope,
  });
  const policyResponse = await admittedFetch(
    state.command_id,
    state.package_ref,
    1,
    "/host/policy",
    policyBody,
  );
  assert.equal(
    policyResponse.status,
    200,
    `persisted policy was not available after restart: ${await policyResponse.clone().text()}`,
  );
  const positionPath =
    `/host/instances/${encodeURIComponent(state.instance_ref)}/position`;
  const positionResponse = await admittedFetch(
    state.command_id,
    state.package_ref,
    1,
    positionPath,
  );
  assert.equal(
    positionResponse.status,
    200,
    `persisted instance was not available after restart: ${await positionResponse.clone().text()}`,
  );
  assert.deepEqual(await positionResponse.json(), state.position);
  console.log(`private Durable workflow restart persistence passed: ${state.instance_ref}`);
}

switch (mode) {
  case "admission":
    await admissionProof();
    break;
  case "open":
    await openProof();
    break;
  case "resume":
    await resumeProof();
    break;
  default:
    throw new Error(`unknown private staging test mode: ${mode}`);
}
