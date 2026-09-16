import worker, { WorkflowInstance as RuntimeWorkflowInstance, type Env } from "./index";
import privateHome from "./private-home";
import {
  canonicalJson,
  p256JwkToGovernanceHex,
  sha256Hex,
  type DurableWorkflowGrant,
} from "./private-home-protocol";

const TEST_HOME_KEY_ID = "test-home-key:ephemeral";
const TEST_HOME_SIGNER = "authority:private-home:test";
const generatedTestHomeKeys = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);
if (!("publicKey" in generatedTestHomeKeys)) {
  throw new Error("test Home signer did not generate a key pair");
}
const testHomeKeys: CryptoKeyPair = generatedTestHomeKeys;
const exportedTestHomePublicKey = await crypto.subtle.exportKey(
  "jwk",
  testHomeKeys.publicKey,
);
if (exportedTestHomePublicKey instanceof ArrayBuffer) {
  throw new Error("test Home public key did not export as JWK");
}
const projectedTestHomeGovernanceKey = p256JwkToGovernanceHex(
  exportedTestHomePublicKey,
);
if (!projectedTestHomeGovernanceKey) {
  throw new Error("test Home key did not project to a governance key");
}
const testHomeGovernanceKey: string = projectedTestHomeGovernanceKey;
const testNormWorkerKeys = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
) as CryptoKeyPair;
const testNormWorkerJwk = await crypto.subtle.exportKey("jwk", testNormWorkerKeys.publicKey);
if (testNormWorkerJwk instanceof ArrayBuffer) {
  throw new Error("test norm worker key did not export as JWK");
}
const testNormWorkerKey = p256JwkToGovernanceHex(testNormWorkerJwk);
if (!testNormWorkerKey) throw new Error("test norm worker key is not a P-256 point");
const testNormSuccessorKeys = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
) as CryptoKeyPair;
const testNormSuccessorJwk = await crypto.subtle.exportKey("jwk", testNormSuccessorKeys.publicKey);
if (testNormSuccessorJwk instanceof ArrayBuffer) throw new Error("test successor key is not JWK");
const testNormSuccessorKey = p256JwkToGovernanceHex(testNormSuccessorJwk);
if (!testNormSuccessorKey) throw new Error("test successor key is not a P-256 point");



function base64(bytes: ArrayBuffer | Uint8Array): string {
  const value =
    bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function signTestHomeGrant(
  grant: DurableWorkflowGrant,
): Promise<Response> {
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    testHomeKeys.privateKey,
    new TextEncoder().encode(canonicalJson(grant)),
  );
  const encoded = base64(
    new TextEncoder().encode(JSON.stringify(grant)),
  )
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  return Response.json({
    grant: encoded,
    signature: base64(signature),
  });
}

const TEST_HOME_EPOCH = 1;
const TEST_HOME_AUTHORITY = "gaugedesk";

/// The `:v2` preimage (DR-0063 §5): `:v1`'s fields plus the policy epoch and
/// the authority, so the hosted path can read the epoch from the signature
/// rather than take it from its caller.
function governanceSigningBytes(
  envelopeHash: string,
  signer: string,
  keyId: string,
): Uint8Array {
  let value = "whipplescript-governance-envelope:v2;";
  for (const item of [
    envelopeHash,
    signer,
    "p256-sha256",
    keyId,
    String(TEST_HOME_EPOCH),
    TEST_HOME_AUTHORITY,
  ]) {
    value += `${new TextEncoder().encode(item).byteLength}:${item};`;
  }
  return new TextEncoder().encode(value);
}

async function testHomePolicy(): Promise<Response> {
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
  const envelopeHash = await sha256Hex(
    new TextEncoder().encode(canonical),
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    testHomeKeys.privateKey,
    governanceSigningBytes(
      envelopeHash,
      TEST_HOME_SIGNER,
      testHomeGovernanceKey,
    ),
  );
  return Response.json({
    key_id: TEST_HOME_KEY_ID,
    signer: TEST_HOME_SIGNER,
    envelope_hash: envelopeHash,
    governance_key_id: testHomeGovernanceKey,
    signed_envelope: canonicalJson({
      ...unsigned,
      attestation: {
        algorithm: "p256-sha256",
        authority: TEST_HOME_AUTHORITY,
        envelope_hash: envelopeHash,
        epoch: TEST_HOME_EPOCH,
        key_id: testHomeGovernanceKey,
        signature: [...new Uint8Array(signature)]
          .map((byte) => byte.toString(16).padStart(2, "0"))
          .join(""),
        signer: TEST_HOME_SIGNER,
      },
    }),
  });
}

export { TestDeployment, TestCredentialRegistry } from "./test-doubles";

// Test-only deployment configuration. The ephemeral private key remains here;
// neither commands nor the production Worker can install these bindings.
export class WorkflowInstance extends RuntimeWorkflowInstance {
  private readonly normFixtureEnv: Env;
  constructor(ctx: DurableObjectState, env: Env) {
    const configured = {
      ...env,
      WHIP_NORM_TRUST: JSON.stringify({
        bindings: [
          { principal: "norm-owner", algorithm: "p256-sha256", key_id: testHomeGovernanceKey },
          { principal: "norm-worker", algorithm: "p256-sha256", key_id: testNormWorkerKey },
          { principal: "norm-owner", algorithm: "p256-sha256", key_id: testNormSuccessorKey },
        ],
        creation_grants: [{ creator: "norm-worker", owner: "norm-owner" }],
      }),
    };
    super(ctx, configured);
    this.normFixtureEnv = configured;
  }

  // Only the test harness calls this through runInDurableObject. No production
  // route or command can alter the deployment's trust document.
  configureNormTestExecutor(endpoint?: string, epoch?: string, runtime?: string): void {
    this.normFixtureEnv.WHIP_EXECUTOR_URL = endpoint;
    this.normFixtureEnv.WHIP_COMPUTE_ENV_HASH = epoch;
    this.normFixtureEnv.WHIP_NORM_RUNTIME = runtime;
  }

  configureNormTestPlanning(deployment: { planning?: string; runtime?: string; image_binding?: string; deployed_image?: string }): void {
    this.normFixtureEnv.WHIP_NORM_PLANNING = deployment.planning;
    this.normFixtureEnv.WHIP_NORM_RUNTIME = deployment.runtime;
    this.normFixtureEnv.WHIP_NORM_IMAGE_BINDING = deployment.image_binding;
    this.normFixtureEnv.WHIP_NORM_DEPLOYMENT_IMAGE = deployment.deployed_image;
  }

  configureNormTestPublicBindings(public_bindings: unknown[], restorations: unknown[]): void {
    this.normFixtureEnv.WHIP_NORM_TRUST = JSON.stringify({
      bindings: [], public_bindings, creation_grants: [], restorations,
    });
  }

  configureNormTestRestorations(restorations: unknown[]): void {
    const trust = JSON.parse(this.normFixtureEnv.WHIP_NORM_TRUST!);
    this.normFixtureEnv.WHIP_NORM_TRUST = JSON.stringify({
      ...trust, creation_grants: [], restorations,
    });
  }
}

async function testNormSignature(binding: string, statement: unknown): Promise<string> {
  const keys = binding === "norm-worker" ? testNormWorkerKeys
    : binding === "norm-successor" ? testNormSuccessorKeys : testHomeKeys;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, keys.privateKey,
    new TextEncoder().encode("whipplescript.norm.event.v1\0" + JSON.stringify(statement)),
  );
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function testNormSign(principal: string, nonce: string, action: unknown): Promise<Response> {
  const worker = principal === "norm-worker";
  const successor = principal === "norm-successor";
  const statement = {
    protocol: "whipplescript.norm/v1",
    actor: {
      principal: successor ? "norm-owner" : principal,
      algorithm: "p256-sha256",
      key_id: worker ? testNormWorkerKey : successor ? testNormSuccessorKey : testHomeGovernanceKey,
    },
    nonce,
    created_at: "2026-09-05T00:00:00Z",
    action,
  };
  return Response.json({ statement, signature: await testNormSignature(principal, statement) });
}

async function testNormBootstrap(url: URL): Promise<Response> {
  return testNormSign(
    url.searchParams.get("principal") ?? "norm-owner", "hosted-norm-genesis", {
      act: "bootstrap",
      creator: url.searchParams.get("creator") ?? "norm-worker",
      charter: { vocabularies: [], owner_scopes: [] },
    },
  );
}
export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/__test/norm/cosign") {
      const { binding, statement } = await request.json<{ binding: string; statement: unknown }>();
      return Response.json({ signature: await testNormSignature(binding, statement) });
    }
    if (request.method === "POST" && url.pathname === "/__test/norm/sign") {
      const { principal, nonce, action } = await request.json<{
        principal: string; nonce: string; action: unknown;
      }>();
      return testNormSign(principal, nonce, action);
    }
    if (request.method === "GET" && url.pathname === "/__test/norm/bootstrap") {
      return testNormBootstrap(url);
    }
    if (
      request.method === "GET" &&
      url.pathname === "/__test/private-home/policy"
    ) {
      return testHomePolicy();
    }
    if (
      request.method === "POST" &&
      url.pathname === "/__test/private-home/sign"
    ) {
      return signTestHomeGrant(
        await request.json<DurableWorkflowGrant>(),
      );
    }
    if (url.pathname.startsWith("/v1/homes/")) {
      return privateHome.fetch(
        request,
        {
          ...env,
          HOME_ADMISSION_KEYS: JSON.stringify({
            [TEST_HOME_KEY_ID]: exportedTestHomePublicKey,
          }),
        },
        ctx,
      );
    }
    return worker.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
