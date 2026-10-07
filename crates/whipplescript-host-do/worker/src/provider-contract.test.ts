import assert from "node:assert/strict";
import test from "node:test";
import contractJson from "../../../whipplescript-kernel/src/provider_contract.json" with { type: "json" };
import {
  CREDENTIAL_HEADERS,
  DURABLE_OBJECT_PROVIDERS,
  OUTPUT_LIMIT_FIELDS,
  credentialHeader,
  outputLimitField,
  requestPath,
  resolveWire,
} from "./provider-contract.ts";

test("the door hosts exactly the identities whose doors name it", () => {
  // `HostedProvider` is every contract identity but `xai-grok`; this holds the
  // runtime set to the same answer, read from `doors`.
  const declared = Object.keys(contractJson.providers).filter((name) => name !== "xai-grok");
  assert.deepEqual([...DURABLE_OBJECT_PROVIDERS].sort(), declared.sort());
});

test("each identity resolves its default wire, path and credential header", () => {
  const cases: [string, string, string, string][] = [
    ["openai", "", "openai-responses", "/v1/responses"],
    ["openai-generic", "/v1", "openai-chat-compat", "/chat/completions"],
    ["xai", "/v1", "openai-chat-compat", "/chat/completions"],
    ["anthropic", "", "anthropic-messages", "/v1/messages"],
    ["openai-codex", "", "openai-responses", "/backend-api/codex/responses"],
  ];
  for (const [provider, admittedPath, wire, path] of cases) {
    const resolved = resolveWire(provider, admittedPath);
    assert.equal(resolved, wire, provider);
    assert.equal(requestPath(provider, resolved), path, provider);
  }
  assert.deepEqual(credentialHeader("anthropic-messages", "k"), ["x-api-key", "k"]);
  assert.deepEqual(credentialHeader("openai-chat-compat", "k"), ["authorization", "Bearer k"]);
});

test("the gateway reads its surface off the admitted path, and a declaration wins", () => {
  const base = "/v1/0123456789abcdef0123456789abcdef/gw";
  assert.equal(resolveWire("cloudflare-ai-gateway", `${base}/compat`), "openai-chat-compat");
  assert.equal(resolveWire("cloudflare-ai-gateway", `${base}/anthropic`), "anthropic-messages");
  assert.equal(resolveWire("cloudflare-ai-gateway", `${base}/openai`), "openai-responses");
  // The unified-billing fallback's base has no surface suffix: the default.
  assert.equal(resolveWire("cloudflare-ai-gateway", "/client/v4/accounts/a/ai/v1"), "openai-chat-compat");
  assert.equal(
    resolveWire("openai-generic", "/v1", "coerced-tools"),
    "coerced-tools",
  );
  // A declaration the identity does not admit is not taken.
  assert.equal(resolveWire("anthropic", "", "openai-responses"), "anthropic-messages");
});

test("output-limit spellings come from the wire, or the identity's override", () => {
  assert.equal(outputLimitField("openai", "openai-responses"), "max_output_tokens");
  assert.equal(outputLimitField("openai-generic", "openai-chat-compat"), "max_tokens");
  assert.equal(outputLimitField("anthropic", "anthropic-messages"), "max_tokens");
  assert.equal(
    outputLimitField("cloudflare-ai-gateway", "openai-chat-compat"),
    "max_completion_tokens",
  );
  assert.equal(outputLimitField("cloudflare-ai-gateway", "anthropic-messages"), "max_tokens");
  assert.deepEqual(
    [...OUTPUT_LIMIT_FIELDS].sort(),
    ["max_completion_tokens", "max_output_tokens", "max_tokens"],
  );
  assert.deepEqual(
    [...CREDENTIAL_HEADERS].sort(),
    ["authorization", "chatgpt-account-id", "x-api-key"],
  );
});
