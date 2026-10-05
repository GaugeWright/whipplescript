import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { packageDocuments, sha256 } from "./integration-helpers";
import { durableWorkflowObjectName, type DurableWorkflowGrant, type OriginalPolicyRef } from "./private-home-protocol";

const HOME = "home:project-policy-test";
const TENANT = "tenant:project-policy-test";
const PROJECT = "project:project-policy-test";
type OriginalFixture = { key_id: string; signer: string; envelope_hash: string; governance_key_id: string; signed_envelope: string };
let legacy: OriginalFixture;
let modern: OriginalFixture;
let current: { key_id: string; signer: string };
let packageDocs: Awaited<ReturnType<typeof packageDocuments>>;

function originalPolicy(fixture = legacy, epoch = 41): OriginalPolicyRef {
  return { epoch, envelope_hash: fixture.envelope_hash, signer: fixture.signer, key_id: fixture.governance_key_id };
}

async function request(
  command: string,
  path: string,
  body: string,
  changes: Partial<DurableWorkflowGrant> = {},
  original = originalPolicy(),
  direct?: { object?: string; body?: string; signer?: string; key?: string; signature?: string },
): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  const grant: DurableWorkflowGrant = {
    version: 2, key_id: current.key_id, governance_signer: current.signer,
    home_id: HOME, tenant_id: TENANT, project_id: PROJECT,
    command_id: command, attempt_id: `attempt:${command}:1`, epoch: 1,
    work_target_basis: "whipple:cut:project-policy", payload_digest: `sha256:${"1".repeat(64)}`,
    profile: "durable_workflow", package_ref: packageDocs.version_ref,
    capabilities: ["chat", "http_effect"], credential_class: "private-home",
    max_spend_nanos_usd: 0, retention_seconds: 3600,
    callback_ref: "https://private-home-broker.test/v1/model-egress",
    request_method: "POST", request_path: path, request_body_sha256: await sha256(body),
    original_policy: original, issued_at: now, expires_at: now + 120,
    ...changes,
  };
  const signer = grant.version === 1 ? "/__test/private-home/sign" : "/__test/project-home/sign";
  const signed = await SELF.fetch(`https://runtime.test${signer}`, {
    method: "POST", body: JSON.stringify(grant),
  });
  expect(signed.status).toBe(200);
  const proof = await signed.json<{ grant: string; signature: string }>();
  if (direct) {
    const objectName = direct.object ?? durableWorkflowObjectName({
      home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: command,
    });
    const stub = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(objectName));
    return stub.fetch(new Request(`https://instance${path}`, {
      method: "POST", headers: { authorization: "Bearer control-token", "content-type": "application/json",
        "x-gaugewright-private-governance-signer": direct.signer ?? current.signer,
        "x-gaugewright-private-governance-key": direct.key ?? current.key_id,
        "x-gaugewright-private-callback": grant.callback_ref,
        "x-gaugewright-private-execution-grant": proof.grant,
        "x-gaugewright-private-execution-signature": direct.signature ?? proof.signature },
      body: direct.body ?? body,
    }));
  }
  const route = `/v1/homes/${encodeURIComponent(grant.home_id)}/tenants/${encodeURIComponent(grant.tenant_id)}`
    + `/projects/${encodeURIComponent(grant.project_id)}/commands/${encodeURIComponent(command)}/attempts/1${path}`;
  return SELF.fetch(`https://runtime.test${route}`, {
    method: "POST", headers: { "content-type": "application/json",
      "x-gaugewright-execution-grant": proof.grant, "x-gaugewright-execution-signature": proof.signature },
    body,
  });
}

describe("project Home original policy verification", () => {
  beforeAll(async () => {
    legacy = await (await SELF.fetch("https://runtime.test/__test/private-home/policy?legacy=1")).json<OriginalFixture>();
    modern = await (await SELF.fetch("https://runtime.test/__test/private-home/policy")).json<OriginalFixture>();
    current = await (await SELF.fetch("https://runtime.test/__test/project-home/identity")).json<typeof current>();
    packageDocs = await packageDocuments();
  });

  it("replays an original V1 policy under a different current project root and survives eviction", async () => {
    expect(current.key_id).not.toBe(legacy.governance_key_id);
    expect(current.signer).not.toBe(legacy.signer);
    const command = "command:retained-original";
    const original = originalPolicy();
    const policyBody = JSON.stringify({ epoch: original.epoch, signed_envelope: legacy.signed_envelope });
    const policy = await request(command, "/host/policy", policyBody);
    expect(policy.status, await policy.clone().text()).toBe(201);
    expect(await policy.json()).toEqual(original);
    const body = JSON.stringify({ command: { protocol: "whipplescript.host.v1", request_id: "open-retained-original",
      package_version_ref: packageDocs.version_ref, policy: original }, package: packageDocs });
    const opened = await request(command, "/host/instances/open", body);
    expect(opened.status, await opened.clone().text()).toBe(201);
    const first = await opened.json<{ instance_ref: string }>();
    const stub = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(durableWorkflowObjectName({
      home_id: HOME, tenant_id: TENANT, project_id: PROJECT, command_id: command,
    })));
    await runInDurableObject(stub, async (_instance, state) => {
      const roots = state.storage.sql.exec<{ signer: string; key: string }>(
        "SELECT signer, key FROM private_governance_root WHERE singleton = 1",
      ).toArray();
      expect(roots).toEqual([{ signer: current.signer, key: current.key_id }]);
      const retained = await state.storage.get<{ signed_envelope: string }>(`host-policy:${original.epoch}:${original.envelope_hash}`);
      expect(retained?.signed_envelope).toBe(legacy.signed_envelope);
    });
    await evictDurableObject(stub);
    const replay = await request(command, "/host/instances/open", body);
    expect(replay.status, await replay.clone().text()).toBe(201);
    expect((await replay.json<{ instance_ref: string }>()).instance_ref).toBe(first.instance_ref);
  });

  it("refuses a correctly signed grant for another Home, tenant, project, signer or key", async () => {
    const body = JSON.stringify({ epoch: 41, signed_envelope: legacy.signed_envelope });
    for (const field of ["home_id", "tenant_id", "project_id", "governance_signer", "key_id"] as const) {
      const response = await request(`command:foreign-${field}`, "/host/policy", body, { [field]: `other:${field}` });
      expect(response.status, await response.clone().text()).toBe(403);
    }
  });

  it("refuses a policy epoch inconsistent with the authenticated original reference", async () => {
    const wrongBody = JSON.stringify({ epoch: 42, signed_envelope: legacy.signed_envelope });
    const wrong = await request("command:wrong-original-epoch", "/host/policy", wrongBody);
    expect(wrong.status, await wrong.clone().text()).toBe(403);
    const substituted = await request("command:wrong-signed-epoch", "/host/policy",
      JSON.stringify({ epoch: 41, signed_envelope: modern.signed_envelope }), {}, originalPolicy(modern));
    expect(substituted.status, await substituted.clone().text()).toBe(403);
    const correct = await request("command:modern-original-epoch", "/host/policy",
      JSON.stringify({ epoch: 1, signed_envelope: modern.signed_envelope }), {}, originalPolicy(modern, 1));
    expect(correct.status, await correct.clone().text()).toBe(201);
  });

  it("the object independently refuses forged headers, signatures, bytes and another object identity", async () => {
    const body = JSON.stringify({ epoch: 41, signed_envelope: legacy.signed_envelope });
    const attempts = [
      { signer: legacy.signer },
      { key: legacy.governance_key_id },
      { signature: "A".repeat(88) },
      { body: `${body} ` },
      { object: "a-client-selected-object" },
    ];
    for (const [index, direct] of attempts.entries()) {
      const response = await request(`command:direct-refusal-${index}`, "/host/policy", body, {}, originalPolicy(), direct);
      expect(response.status, await response.clone().text()).toBe(403);
    }
    const valid = await request("command:direct-admitted", "/host/policy", body, {}, originalPolicy(), {});
    expect(valid.status, await valid.clone().text()).toBe(201);
  });

  it("a legacy installation signer cannot preempt the registered project Home", async () => {
    const body = JSON.stringify({ epoch: 1, signed_envelope: modern.signed_envelope });
    const changes: Partial<DurableWorkflowGrant> = {
      version: 1, key_id: legacy.key_id, governance_signer: legacy.signer, original_policy: undefined,
    };
    const outer = await request("command:legacy-root-preemption", "/host/policy", body, changes);
    expect(outer.status, await outer.clone().text()).toBe(403);
    const direct = await request("command:legacy-direct-preemption", "/host/policy", body, changes, originalPolicy(), {
      signer: legacy.signer, key: legacy.governance_key_id,
    });
    expect(direct.status, await direct.clone().text()).toBe(403);
  });
});
