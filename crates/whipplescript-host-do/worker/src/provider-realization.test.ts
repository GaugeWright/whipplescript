import assert from "node:assert/strict";
import test from "node:test";
import { MODEL_AUTH_SENTINEL, performDirectProviderFetch } from "./model-broker.ts";
import { canonicalCredentialClassRef } from "./credential-class-ref.ts";
import {
  bindExactPublicCredential,
  type HostTurnAdmission,
  resolveAdmittedProvider,
} from "./provider-realization.ts";

const admission: HostTurnAdmission = {
  provider_binding_id: "gaugedesk:provider:primary",
  credential_id: "gaugedesk:credential:v2:account:616c696365:openai:4",
  placement_ceiling_ref: "gaugedesk:placement:do",
  provider: "openai",
  model: "gpt-5",
  base_url: "https://api.openai.com",
};

test("signed admission dynamically realizes the model broker without a provider map", () => {
  const resolved = resolveAdmittedProvider(admission, {
    WHIP_MODEL_BROKER_URL: "https://home.example/internal/model-egress",
    WHIP_MODEL_BROKER_TOKEN: "hop-token",
  });
  assert.deepEqual(resolved, {
    credential_id: admission.credential_id,
    provider: "openai",
    model: "gpt-5",
    base_url: "https://api.openai.com",
    execution: "model-broker",
    api_key: MODEL_AUTH_SENTINEL,
  });
});

test("private execution grant realizes its exact Home callback", () => {
  const resolved = resolveAdmittedProvider(admission, {
    WHIP_MODEL_BROKER_URL: "https://home.example/internal/model-egress",
    WHIP_MODEL_BROKER_EXECUTION_GRANT: "grant",
    WHIP_MODEL_BROKER_EXECUTION_SIGNATURE: "signature",
  });
  assert.equal(resolved.execution, "model-broker");
  assert.equal(resolved.credential_id, admission.credential_id);
});

test("codex admission uses only the authenticated local broker sentinel", () => {
  const codex: HostTurnAdmission = {
    ...admission,
    credential_id: "gaugedesk:credential:v2:account:616c696365:openai-codex:1",
    provider: "openai-codex",
    model: "gpt-5.5",
    base_url: "https://chatgpt.com",
  };
  const resolved = resolveAdmittedProvider(codex, {
    WHIP_MODEL_BROKER_URL: "https://outbound-session.example/internal/local-model-egress",
    WHIP_MODEL_BROKER_TOKEN: "session-token",
  });
  assert.equal(resolved.execution, "model-broker");
  assert.equal(resolved.api_key, MODEL_AUTH_SENTINEL);
  assert.equal(resolved.credential_id, codex.credential_id);
});

test("missing broker transport fails closed with no Worker-secret fallback", () => {
  assert.throws(
    () => resolveAdmittedProvider(admission, {}),
    /has no model broker/,
  );
});

test("public session realizes the admitted provider directly inside its DO", () => {
  const resolved = resolveAdmittedProvider(
    admission,
    {},
    "direct",
  );
  assert.deepEqual(resolved, {
    credential_id: admission.credential_id,
    provider: "openai",
    model: "gpt-5",
    base_url: "https://api.openai.com",
    execution: "direct",
    api_key: MODEL_AUTH_SENTINEL,
  });
});

test("public session preserves the signed class while binding the exact deployment ref", () => {
  const admitted = resolveAdmittedProvider(admission, {}, "direct");
  const resolved = bindExactPublicCredential(
    admitted,
    "credential:deployment:theory-a:openai:v3",
    admission.credential_id,
  );
  assert.equal(resolved.credential_class, admission.credential_id);
  assert.equal(
    resolved.credential_id,
    "credential:deployment:theory-a:openai:v3",
  );
  assert.throws(
    () => bindExactPublicCredential(admitted, "", admission.credential_id),
    /requires an exact deployment reference/,
  );
});

test("public direct provider rejects subscription credentials", () => {
  assert.throws(
    () =>
      resolveAdmittedProvider(
        { ...admission, provider: "openai-codex" },
        {},
        "direct",
      ),
    /cannot receive an account OAuth credential/,
  );
});

// ---- managed funding (ADR 0085 §1/§3/§6, FUND-1) -------------------------

const gatewayAdmission: HostTurnAdmission = {
  ...admission,
  credential_id: "gaugedesk:managed-plan:v1:74656e616e74:73747269706500",
  provider: "cloudflare-ai-gateway",
  base_url:
    "https://gateway.ai.cloudflare.com/v1/1689dd452ba2d2d8eb1f3c364c92b3f4/gaugewright-panels/compat",
};

test("managed funding realizes the gateway without any customer credential", () => {
  const resolved = resolveAdmittedProvider(
    gatewayAdmission,
    { WHIP_GATEWAY_TOKEN: "gateway-token" },
    "managed",
  );
  assert.equal(resolved.execution, "managed");
  assert.equal(resolved.provider, "cloudflare-ai-gateway");
  // WhippleScript sees only the sentinel; the token is injected at the final
  // fetch, so no provider secret enters the runtime or its snapshots.
  assert.equal(resolved.api_key, MODEL_AUTH_SENTINEL);
  // The admitted id stays the *funding* reference. Nothing turned it into a
  // credential reference, because managed funding has no credential to resolve.
  assert.match(resolved.credential_id, /^gaugedesk:managed-plan:v1:/);
});

test("managed funding fails loudly when the runtime holds no gateway token", () => {
  // The failure that must never be a fallback: a managed turn that quietly ran
  // on some other credential would bill the wrong party, which is the entire
  // reason this is its own execution class.
  assert.throws(
    () => resolveAdmittedProvider(gatewayAdmission, {}, "managed"),
    /managed funding has no gateway token/,
  );
});

test("managed funding refuses a provider that is not the metered gateway", () => {
  // Guards against a deployment reaching the service's credits through an
  // ordinary provider by declaring managed funding.
  assert.throws(
    () =>
      resolveAdmittedProvider(
        { ...gatewayAdmission, provider: "openai" },
        { WHIP_GATEWAY_TOKEN: "gateway-token" },
        "managed",
      ),
    /requires the metered gateway/,
  );
});

test("the gateway is not silently usable as a BYOK direct provider", () => {
  // A `direct` turn resolves a *customer* credential by reference. Letting the
  // gateway through that path would spend service credits while reporting a
  // customer-funded turn, so the two stay distinguishable by execution class:
  // direct binds an exact deployment reference, managed never does.
  const direct = resolveAdmittedProvider(
    gatewayAdmission,
    { WHIP_GATEWAY_TOKEN: "gateway-token" },
    "direct",
  );
  assert.equal(direct.execution, "direct");
  assert.throws(
    () => bindExactPublicCredential(
      resolveAdmittedProvider(
        gatewayAdmission,
        { WHIP_GATEWAY_TOKEN: "gateway-token" },
        "managed",
      ),
      "credential:public:abc:openai:def",
      gatewayAdmission.credential_id,
    ),
    /requires an exact deployment reference/,
  );
});


for (const canonical of [false, true]) {
  test(`public ${canonical ? "canonical" : "legacy"} class reaches the exact registry credential`, async () => {
    const credentialClass = "openai-api-key";
    const exactRef = `credential:public:${"a".repeat(64)}:openai:${"b".repeat(32)}`;
    const admitted = resolveAdmittedProvider({
      ...admission,
      credential_id: canonical ? canonicalCredentialClassRef(credentialClass) : credentialClass,
    }, {}, "direct");
    const bound = bindExactPublicCredential(admitted, exactRef, credentialClass);
    const lookups: string[] = [];
    let fetched = 0;
    const request = {
      url: "https://api.openai.com/v1/responses",
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]] as [string, string][],
      body: { model: "gpt-5" },
    };
    const fetcher = async (_url: string, init: RequestInit) => {
      fetched += 1;
      assert.equal(new Headers(init.headers).get("authorization"), "Bearer synthetic-registry-key");
      return Response.json({ output: [] });
    };
    // The registry retains the raw class; it never returns the signed
    // envelope's canonical credential reference as a class.
    const result = await performDirectProviderFetch(request, bound, {
      resolve: async (ref) => {
        lookups.push(ref);
        return { provider: "openai", credential_class: credentialClass, api_key: "synthetic-registry-key" };
      },
    }, fetcher);
    assert.equal(JSON.parse(result).status, 200);
    assert.deepEqual(lookups, [exactRef]);
    assert.equal(fetched, 1);
    assert.equal(bound.credential_class, credentialClass);
    assert.equal(admitted.credential_id, canonical ? canonicalCredentialClassRef(credentialClass) : credentialClass);

    for (const entry of [
      { provider: "anthropic", credential_class: credentialClass },
      { provider: "openai", credential_class: "another-openai-key" },
      { provider: "openai", credential_class: canonicalCredentialClassRef(credentialClass) },
    ]) {
      await assert.rejects(performDirectProviderFetch(request, bound, {
        resolve: async (ref) => {
          assert.equal(ref, exactRef);
          return { ...entry, api_key: "wrong-key" };
        },
      }, fetcher), /does not match the admitted provider and class/);
    }
    assert.equal(fetched, 1, "mismatched registry metadata must refuse before egress");
  });
}

test("public class binding refuses unrelated and empty closure classes", () => {
  for (const credentialId of ["openai-api-key", canonicalCredentialClassRef("openai-api-key")]) {
    const admitted = resolveAdmittedProvider({ ...admission, credential_id: credentialId }, {}, "direct");
    for (const rawClass of ["", " ", "anthropic-api-key", "OPENAI-API-KEY", "openai-api-key "]) {
      assert.throws(
        () => bindExactPublicCredential(admitted, "credential:deployment:exact", rawClass),
        /does not match the signed admission/,
      );
    }
  }
  // Even a syntactically canonical ref is not authority to substitute a
  // different class or to treat malformed encoding as equivalent.
  for (const credentialId of [canonicalCredentialClassRef("anthropic-api-key"), "credential:gaugedesk/class/xyz"]) {
    const admitted = resolveAdmittedProvider({ ...admission, credential_id: credentialId }, {}, "direct");
    assert.throws(
      () => bindExactPublicCredential(admitted, "credential:deployment:exact", "openai-api-key"),
      /does not match the signed admission/,
    );
  }
});
