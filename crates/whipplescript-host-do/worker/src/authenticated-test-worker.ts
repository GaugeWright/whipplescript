import worker, { WorkflowInstance, type Env } from "./index";
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

export { WorkflowInstance };
export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
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
