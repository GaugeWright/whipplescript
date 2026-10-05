import assert from "node:assert/strict";
// grant-field-mutations
import test from "node:test";
import {
  canonicalJson,
  durableWorkflowObjectName,
  homeAdmissionKey,
  projectHomeAddress,
  p256JwkToGovernanceHex,
  validateDurableWorkflowGrant,
  verifyP256GrantSignature,
  validOriginalPolicyRef,
  type DurableWorkflowGrant,
  type HomeAdmissionBinding,
} from "./private-home-protocol.ts";

const now = 1_900_000_000;

function grant(): DurableWorkflowGrant {
  return {
    version: 1,
    key_id: "home-key:1",
    governance_signer: "authority:one",
    home_id: "home:one",
    tenant_id: "tenant:one",
    project_id: "project:one",
    work_target_basis: "whipple:cut:abc",
    command_id: "command:one",
    attempt_id: "attempt:one",
    payload_digest: `sha256:${"1".repeat(64)}`,
    epoch: 1,
    profile: "durable_workflow",
    package_ref: "sha256:abc",
    capabilities: ["model.openai.responses", "resource.read"],
    credential_class: "private-home",
    max_spend_nanos_usd: 1_000_000,
    retention_seconds: 86_400,
    callback_ref: "https://home.example/internal/model-egress",
    request_method: "POST",
    request_path: "/host/turns",
    request_body_sha256: "a".repeat(64),
    issued_at: now,
    expires_at: now + 300,
  };
}

test("private Durable workflow grant is exact and short-lived", () => {
  assert.equal(validateDurableWorkflowGrant(grant(), now), undefined);
  const workspace = grant();
  workspace.capabilities.push("workspace.write");
  assert.match(validateDurableWorkflowGrant(workspace, now) ?? "", /workspace capability/);
  const process = grant();
  process.capabilities.push("command.run");
  assert.match(validateDurableWorkflowGrant(process, now) ?? "", /workspace capability/);
  const longLived = grant();
  longLived.expires_at = now + 901;
  assert.match(validateDurableWorkflowGrant(longLived, now) ?? "", /short-lived/);
});

function projectGrant(): DurableWorkflowGrant {
  return {
    ...grant(),
    version: 2,
    original_policy: {
      epoch: 12,
      envelope_hash: "b".repeat(64),
      signer: "authority:original",
      key_id: `04${"1".repeat(128)}`,
    },
  };
}

test("project Home grants require the exact original policy reference", () => {
  const admitted = projectGrant();
  assert.equal(validateDurableWorkflowGrant(admitted, now), undefined);
  for (const field of ["epoch", "envelope_hash", "signer", "key_id"] as const) {
    const missing = structuredClone(admitted);
    delete (missing.original_policy as unknown as Record<string, unknown>)[field];
    assert.match(validateDurableWorkflowGrant(missing, now) ?? "", /original policy/);
  }
  const wrongEpoch = structuredClone(admitted);
  wrongEpoch.original_policy!.epoch = 0;
  assert.match(validateDurableWorkflowGrant(wrongEpoch, now) ?? "", /original policy/);
  const implicitEpoch = structuredClone(admitted);
  delete implicitEpoch.original_policy;
  assert.match(validateDurableWorkflowGrant(implicitEpoch, now) ?? "", /original policy/);
  assert.equal(validOriginalPolicyRef({ ...admitted.original_policy, unexpected: true }), false);
  assert.equal(validOriginalPolicyRef({ ...admitted.original_policy, key_id: `03${"1".repeat(64)}` }), true);
  const legacy = structuredClone(admitted);
  legacy.version = 1;
  assert.match(validateDurableWorkflowGrant(legacy, now) ?? "", /original policy/);
});

test("missing execution identities are refused rather than regex-coerced", () => {
  for (const field of ["home_id", "tenant_id", "project_id", "governance_signer", "key_id"] as const) {
    const missing = structuredClone(grant()) as unknown as Record<string, unknown>;
    delete missing[field];
    assert.match(validateDurableWorkflowGrant(missing as unknown as DurableWorkflowGrant, now) ?? "", /identity/);
  }
});

test("deployment admission binds an exact Home, tenant, project, signer and key", async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const admitted = projectGrant();
  const binding: HomeAdmissionBinding = {
    home_id: admitted.home_id,
    tenant_id: admitted.tenant_id,
    project_id: admitted.project_id,
    governance_signer: admitted.governance_signer,
    key_id: admitted.key_id,
    public_key: publicKey,
  };
  const configuration = JSON.stringify([binding]);
  assert.deepEqual(homeAdmissionKey(configuration, admitted), publicKey);
  assert.equal(projectHomeAddress(configuration, admitted), true);
  assert.equal(projectHomeAddress(configuration, { ...admitted, project_id: "other-project" }), true);
  assert.equal(projectHomeAddress(configuration, { ...admitted, home_id: "other-home" }), true);
  assert.equal(projectHomeAddress(configuration, { home_id: "other-home", project_id: "other-project" }), false);
  assert.equal(projectHomeAddress(undefined, admitted), false);
  for (const field of ["home_id", "tenant_id", "project_id", "governance_signer", "key_id"] as const) {
    const substituted = { ...admitted, [field]: `${admitted[field]}:other` };
    assert.equal(homeAdmissionKey(configuration, substituted), undefined, field);
  }
  assert.throws(() => homeAdmissionKey(undefined, admitted), /unavailable/);
  assert.throws(() => homeAdmissionKey("{}", admitted), /unavailable/);
  assert.throws(() => homeAdmissionKey(JSON.stringify([binding, binding]), admitted), /ambiguous/);
  const foreign = { ...binding, home_id: "home:other", project_id: "project:other" };
  assert.throws(() => homeAdmissionKey(JSON.stringify([binding, foreign]), admitted), /ambiguous/);
  const malformed = { ...binding, public_key: { ...publicKey, d: "private-material" } };
  assert.throws(() => homeAdmissionKey(JSON.stringify([malformed]), admitted), /invalid/);
});

test("a Home signature binds every field of the original policy reference", async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const admitted = projectGrant();
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey,
    new TextEncoder().encode(canonicalJson(admitted)));
  const key = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const encoded = Buffer.from(signature).toString("base64");
  assert.equal(await verifyP256GrantSignature(admitted, encoded, key), true);
  for (const field of ["epoch", "envelope_hash", "signer", "key_id"] as const) {
    const changed = structuredClone(admitted);
    const policy = changed.original_policy!;
    (policy as unknown as Record<string, unknown>)[field] = typeof policy[field] === "number"
      ? Number(policy[field]) + 1 : `${policy[field]}:changed`;
    assert.equal(await verifyP256GrantSignature(changed, encoded, key), false, field);
  }
});
test("P-256 signature binds every private grant field", async () => {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const admitted = grant();
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    pair.privateKey,
    new TextEncoder().encode(canonicalJson(admitted)),
  );
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  assert.equal(
    await verifyP256GrantSignature(
      admitted,
      Buffer.from(signature).toString("base64"),
      publicKey,
    ),
    true,
  );
  for (const field of Object.keys(admitted) as (keyof DurableWorkflowGrant)[]) {
    const mutated = structuredClone(admitted) as Record<string, unknown>;
    const value = mutated[field];
    mutated[field] =
      typeof value === "number"
        ? value + 1
        : Array.isArray(value)
          ? [...value, "mutated"]
          : `${String(value)}-mutated`;
    assert.equal(
      await verifyP256GrantSignature(
        mutated as unknown as DurableWorkflowGrant,
        Buffer.from(signature).toString("base64"),
        publicKey,
      ),
      false,
      `signature did not bind ${field}`,
    );
  }
});

test("Home JWK projects to GaugeDesk's exact governance key identity", async () => {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const governanceKey = p256JwkToGovernanceHex(publicKey);
  assert.match(governanceKey ?? "", /^04[0-9a-f]{128}$/);
  assert.equal(
    governanceKey?.slice(2),
    `${Buffer.from(publicKey.x ?? "", "base64url").toString("hex")}${Buffer.from(
      publicKey.y ?? "",
      "base64url",
    ).toString("hex")}`,
  );
  assert.equal(p256JwkToGovernanceHex({ ...publicKey, x: "invalid!" }), undefined);
});

test("private Home object names are collision-free structured tuples", () => {
  const first = {
    home_id: "a:tenant:b",
    tenant_id: "c",
    project_id: "project",
    command_id: "command",
  };
  const second = {
    home_id: "a",
    tenant_id: "b:tenant:c",
    project_id: "project",
    command_id: "command",
  };
  const legacyName = (value: typeof first) =>
    [
      "home",
      value.home_id,
      "tenant",
      value.tenant_id,
      "project",
      value.project_id,
      "command",
      value.command_id,
    ].join(":");
  assert.equal(legacyName(first), legacyName(second));
  assert.notEqual(
    durableWorkflowObjectName(first),
    durableWorkflowObjectName(second),
  );
});
