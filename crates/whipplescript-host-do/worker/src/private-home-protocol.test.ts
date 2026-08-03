import assert from "node:assert/strict";
// grant-field-mutations
import test from "node:test";
import {
  canonicalJson,
  durableWorkflowObjectName,
  p256JwkToGovernanceHex,
  validateDurableWorkflowGrant,
  verifyP256GrantSignature,
  type DurableWorkflowGrant,
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
