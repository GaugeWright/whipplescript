import assert from "node:assert/strict";
import test from "node:test";
import {
  performDirectProviderFetch,
  MODEL_AUTH_SENTINEL,
  MODEL_EGRESS_PROTOCOL,
  MODEL_EGRESS_STREAM_PROTOCOL,
  performManagedGatewayFetch,
  performModelBrokerFetch,
  ResponsesSseDeltaDecoder,
  stripSentinelAuthentication,
} from "./model-broker.ts";

test("Anthropic live projection emits answer text and suppresses thinking", () => {
  const seen: string[] = [];
  const decoder = new ResponsesSseDeltaDecoder((delta) => seen.push(delta), "anthropic");
  decoder.feed('event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"secret"}}\n\n');
  decoder.feed('event: content_block_delta\ndata: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hello"}}\n\n');
  decoder.finish();
  assert.deepEqual(seen, ["Hello"]);
});

const binding = {
  credential_id: "credential:project:alpha:v3",
  credential_class: "managed-openai",
  provider: "openai" as const,
  model: "gpt-test",
  base_url: "https://api.openai.com",
};

function credentialResolver(
  entry: {
    provider: string;
    credential_class?: string;
    api_key: string;
  } | undefined,
) {
  return {
    resolve: async () => entry,
  };
}

test("broker envelope strips provider auth and preserves idempotency", async () => {
  let capturedUrl = "";
  let capturedInit: RequestInit | undefined;
  const result = await performModelBrokerFetch(
    {
      url: "https://api.openai.com/v1/responses",
      headers: [
        ["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`],
        ["content-type", "application/json"],
        ["idempotency-key", "turn-123"],
      ],
      body: { model: "gpt-test", input: "hello" },
    },
    binding,
    { url: "https://home.example/model-egress", token: "broker-token" },
    async (url, init) => {
      capturedUrl = url;
      capturedInit = init;
      return Response.json({
        protocol: MODEL_EGRESS_PROTOCOL,
        status: 200,
        body: { output: [{ type: "message" }] },
        reconciliation_ref: "gateway-request-7",
      });
    },
  );

  assert.equal(capturedUrl, "https://home.example/model-egress");
  const transportHeaders = capturedInit?.headers as Record<string, string>;
  assert.equal(transportHeaders.authorization, "Bearer broker-token");
  assert.equal(transportHeaders["idempotency-key"], "turn-123");
  const envelope = JSON.parse(String(capturedInit?.body));
  assert.equal(envelope.protocol, MODEL_EGRESS_PROTOCOL);
  assert.equal(envelope.credential_ref, binding.credential_id);
  assert.deepEqual(envelope.request.headers, [
    ["content-type", "application/json"],
    ["idempotency-key", "turn-123"],
  ]);
  assert.ok(!JSON.stringify(envelope).includes("broker-token"));
  assert.ok(!JSON.stringify(envelope).includes(MODEL_AUTH_SENTINEL));
  assert.deepEqual(JSON.parse(result), {
    status: 200,
    body: { output: [{ type: "message" }] },
  });
});

test("stream broker relays split provider bytes and publishes text deltas", async () => {
  const deltas: string[] = [];
  const encoder = new TextEncoder();
  const result = await performModelBrokerFetch(
    {
      url: "https://api.openai.com/v1/responses",
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
      body: { stream: true },
    },
    binding,
    { url: "https://home.example/model-egress", token: "broker-token" },
    async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(
          'event: response.output_text.delta\ndata: {"type":"response.output_',
        ));
        controller.enqueue(encoder.encode(
          'text.delta","delta":"hello"}\n\nevent: response.completed\n',
        ));
        controller.enqueue(encoder.encode(
          'data: {"type":"response.completed","response":{"usage":{"output_tokens":1}}}\n\n',
        ));
        controller.close();
      },
    }), {
      headers: {
        "x-whip-model-egress-protocol": MODEL_EGRESS_STREAM_PROTOCOL,
        "x-whip-provider-status": "200",
        "x-whip-provider-content-type": "text/event-stream",
      },
    }),
    (delta) => deltas.push(delta),
  );

  assert.deepEqual(deltas, ["hello"]);
  const decoded = JSON.parse(result);
  assert.equal(decoded.status, 200);
  assert.match(decoded.body, /response\.output_text\.delta/);
});

test("public Session DO streams directly from the signed provider endpoint", async () => {
  const deltas: string[] = [];
  const timing: string[] = [];
  let capturedAuthorization = "";
  const encoder = new TextEncoder();
  const directBinding = {
    ...binding,
    base_url: "https://api.openai.com",
  };
  const result = await performDirectProviderFetch(
    {
      url: `${directBinding.base_url}/v1/responses`,
      headers: [
        ["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`],
        ["content-type", "application/json"],
      ],
      body: { model: "gpt-test", stream: true },
    },
    directBinding,
    credentialResolver({
      provider: directBinding.provider,
      credential_class: directBinding.credential_class,
      api_key: "sk-session-secret",
    }),
    async (_url, init) => {
      capturedAuthorization = new Headers(init.headers).get("authorization") ?? "";
      return new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(
              encoder.encode(
                'data: {"type":"response.output_text.delta","delta":"direct"}\n\n',
              ),
            );
            controller.enqueue(
              encoder.encode(
                'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":2},"output_tokens":1}}}\n\n',
              ),
            );
            controller.close();
          },
        }),
        {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        },
      );
    },
    (delta) => deltas.push(delta),
    (event) => timing.push(event),
  );
  assert.equal(capturedAuthorization, "Bearer sk-session-secret");
  assert.deepEqual(deltas, ["direct"]);
  assert.deepEqual(timing, [
    "direct_provider_fetch_start",
    "direct_provider_headers",
    "direct_provider_first_body_byte",
    "direct_provider_first_text_delta",
    "direct_provider_body_complete",
  ]);
  assert.equal(JSON.parse(result).status, 200);
});

test("OpenAI Responses egress names the output token limit for the provider API", async () => {
  let capturedBody: Record<string, unknown> | undefined;
  await performDirectProviderFetch(
    {
      url: "https://api.openai.com/v1/responses",
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
      body: {
        model: "gpt-5-mini",
        input: "Reply OK",
        max_tokens: 256,
        stream: true,
      },
    },
    { ...binding, model: "gpt-5-mini", base_url: "https://api.openai.com" },
    credentialResolver({
      provider: "openai",
      credential_class: binding.credential_class,
      api_key: "sk-session-secret",
    }),
    async (_url, init) => {
      capturedBody = JSON.parse(String(init.body));
      return new Response(
        'data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1}}}\n\n',
        { headers: { "content-type": "text/event-stream" } },
      );
    },
  );
  assert.deepEqual(capturedBody, {
    model: "gpt-5-mini",
    input: "Reply OK",
    max_output_tokens: 256,
    stream: true,
  });
});

test("Cloudflare gateway chat egress names the completion token limit", async () => {
  let capturedBody: Record<string, unknown> | undefined;
  const gatewayBinding = {
    ...binding,
    provider: "cloudflare-ai-gateway" as const,
    model: "gpt-5-mini",
    base_url: `https://gateway.ai.cloudflare.com/v1/${"a".repeat(32)}/managed/compat`,
  };
  await performDirectProviderFetch(
    {
      url: `${gatewayBinding.base_url}/chat/completions`,
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
      body: { model: "gpt-5-mini", messages: [], max_tokens: 256 },
    },
    gatewayBinding,
    credentialResolver({
      provider: gatewayBinding.provider,
      credential_class: binding.credential_class,
      api_key: "gateway-token",
    }),
    async (_url, init) => {
      capturedBody = JSON.parse(String(init.body));
      return Response.json({ choices: [{ message: { content: "OK" } }] });
    },
  );
  assert.deepEqual(capturedBody, {
    model: "gpt-5-mini",
    messages: [],
    max_completion_tokens: 256,
  });
});

test("provider egress refuses conflicting output token limits", async () => {
  await assert.rejects(
    performDirectProviderFetch(
      {
        url: "https://api.openai.com/v1/responses",
        headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
        body: { max_tokens: 256, max_output_tokens: 512 },
      },
      { ...binding, base_url: "https://api.openai.com" },
      credentialResolver({
        provider: "openai",
        credential_class: binding.credential_class,
        api_key: "sk-session-secret",
      }),
      async () => { throw new Error("must not fetch"); },
    ),
    /conflicting output token limits/,
  );
});

test("public Session DO resolves an owner credential only at final fetch", async () => {
  const credentialRef =
    `credential:public:${"a".repeat(64)}:openai:${"b".repeat(32)}`;
  const directBinding = {
    ...binding,
    credential_id: credentialRef,
    base_url: "https://api.openai.com",
  };
  const resolved: string[] = [];
  let authorization = "";
  await performDirectProviderFetch(
    {
      url: "https://api.openai.com/v1/responses",
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
      body: { stream: true },
    },
    directBinding,
    {
      resolve: async (requestedRef) => {
        resolved.push(requestedRef);
        return {
          credential_ref: requestedRef,
          provider: "openai",
          credential_class: "managed-openai",
          api_key: "sk-owner-secret",
        };
      },
    },
    async (_url, init) => {
      authorization = new Headers(init.headers).get("authorization") ?? "";
      return new Response(
        'data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1}}}\n\n',
        { headers: { "content-type": "text/event-stream" } },
      );
    },
  );
  assert.deepEqual(resolved, [credentialRef]);
  assert.equal(authorization, "Bearer sk-owner-secret");
});

test("direct provider rejection diagnostics contain only bounded metadata", async () => {
  const directBinding = {
    ...binding,
    base_url: "https://api.openai.com",
  };
  const observed: string[] = [];
  const original = console.log;
  console.log = (value?: unknown) => observed.push(String(value));
  try {
    const result = await performDirectProviderFetch(
      {
        url: `${directBinding.base_url}/v1/responses`,
        headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
        body: { model: "gpt-test", stream: true },
      },
      directBinding,
      credentialResolver({
        provider: directBinding.provider,
        credential_class: directBinding.credential_class,
        api_key: "sk-diagnostic-canary",
      }),
      async () =>
        Response.json(
          {
            error: {
              type: "invalid_request_error",
              code: "bad_request",
              param: "tools.0",
              message:
                "unsafe provider prose and sk-diagnostic-canary must not enter logs",
            },
          },
          { status: 400 },
        ),
    );
    assert.equal(JSON.parse(result).status, 400);
  } finally {
    console.log = original;
  }
  assert.equal(observed.length, 1);
  assert.deepEqual(JSON.parse(observed[0]!), {
    event: "gaugewright_direct_provider_rejected",
    status: 400,
    type: "invalid_request_error",
    code: "bad_request",
    param: "tools.0",
  });
  assert.doesNotMatch(observed[0]!, /unsafe|canary/);
});

test("direct provider refuses endpoint drift before fetch", async () => {
  await assert.rejects(
    performDirectProviderFetch(
      {
        url: "https://attacker.example/collect",
        headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
        body: {},
      },
      { ...binding, base_url: "https://api.openai.com" },
      credentialResolver({
        provider: binding.provider,
        credential_class: binding.credential_class,
        api_key: "secret",
      }),
      async () => {
        throw new Error("must not fetch");
      },
    ),
    /escaped the signed provider endpoint/,
  );
});

test("direct provider resolves only the exact admitted credential reference", async () => {
  const request = {
    url: "https://api.openai.com/v1/responses",
    headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]] as [string, string][],
    body: {},
  };
  const fetcher = async () => {
    throw new Error("must not fetch");
  };
  await assert.rejects(
    performDirectProviderFetch(
      request,
      binding,
      credentialResolver(undefined),
      fetcher,
    ),
    /is unavailable/,
  );
  await assert.rejects(
    performDirectProviderFetch(
      request,
      binding,
      credentialResolver({
        provider: "anthropic",
        credential_class: binding.credential_class,
        api_key: "wrong-provider-secret",
      }),
      fetcher,
    ),
    /does not match the admitted provider/,
  );
  await assert.rejects(
    performDirectProviderFetch(
      request,
      binding,
      credentialResolver({
        provider: binding.provider,
        credential_class: "managed-anthropic",
        api_key: "wrong-class-secret",
      }),
      fetcher,
    ),
    /does not match the admitted provider and class/,
  );
});

test("provider credentials cannot cross the broker boundary", () => {
  assert.throws(
    () => stripSentinelAuthentication([["authorization", "Bearer actual-secret"]]),
    /not the broker sentinel/,
  );
  assert.throws(
    () => stripSentinelAuthentication([["cookie", "session=secret"]]),
    /forbidden cookie header/,
  );
  assert.throws(
    () => stripSentinelAuthentication([["content-type", "application\/json"]]),
    /no broker-sentinel authentication/,
  );
});

test("broker configuration and protocol failures are fail-closed", async () => {
  const request = {
    url: "https://api.openai.com/v1/responses",
    headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]] as [string, string][],
    body: {},
  };
  await assert.rejects(
    performModelBrokerFetch(request, binding, { url: "http://broker.example", token: "token" }),
    /must use HTTPS/,
  );
  await assert.rejects(
    performModelBrokerFetch(request, binding, { url: "https://broker.example" }),
    /authorization is unavailable/,
  );
  await performModelBrokerFetch(
    request,
    binding,
    {
      url: "https://home.example/internal/model-egress",
      executionGrant: "signed-grant",
      executionSignature: "signed-signature",
    },
    async (_url, init) => {
      const headers = new Headers(init.headers);
      assert.equal(headers.get("authorization"), null);
      assert.equal(
        headers.get("x-gaugewright-execution-grant"),
        "signed-grant",
      );
      assert.equal(
        headers.get("x-gaugewright-execution-signature"),
        "signed-signature",
      );
      return Response.json({
        protocol: "whipplescript.model-egress.v1",
        status: 200,
        body: {},
      });
    },
  );
  await assert.rejects(
    performModelBrokerFetch(
      request,
      binding,
      { url: "http://127.0.0.1:8789/model-egress", token: "token" },
      async () => Response.json({ protocol: "wrong", status: 200, body: {} }),
    ),
    /wrong protocol/,
  );
});

// ---- managed gateway funding (ADR 0085 §3/§6, FUND-1) --------------------

const gatewayBinding = {
  credential_id: "gaugedesk:managed-plan:v1:74656e616e74:73747269706500",
  credential_class: "managed-openai",
  provider: "cloudflare-ai-gateway" as const,
  model: "openai/gpt-4.1",
  base_url:
    "https://gateway.ai.cloudflare.com/v1/1689dd452ba2d2d8eb1f3c364c92b3f4/gaugewright-panels/compat",
};

// `token` is required rather than defaulted: passing `undefined` to a defaulted
// parameter silently uses the default, which made the no-token case pass while
// actually running with a token.
function gatewayRound(
  fetcher: (url: string, init: RequestInit) => Promise<Response>,
  token: string | undefined,
) {
  return performManagedGatewayFetch(
    {
      url: `${gatewayBinding.base_url}/chat/completions`,
      headers: [
        ["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`],
        ["content-type", "application/json"],
      ],
      body: { model: gatewayBinding.model, stream: false },
    },
    gatewayBinding,
    { token: () => token },
    fetcher,
  );
}

test("a managed round spends the gateway token and no customer credential", async () => {
  let capturedAuthorization = "";
  let capturedByokAlias = "";
  let capturedUrl = "";
  await gatewayRound(async (url, init) => {
    capturedUrl = url;
    const headers = new Headers(init.headers);
    capturedAuthorization = headers.get("authorization") ?? "";
    capturedByokAlias = headers.get("cf-aig-byok-alias") ?? "";
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }, "cf-gateway-token");
  // The gateway's own token, as a Bearer — this is what makes Cloudflare bill
  // the service's unified-billing credits rather than a provider account.
  assert.equal(capturedAuthorization, "Bearer cf-gateway-token");
  // And the sentinel never survives to the wire.
  assert.ok(!capturedAuthorization.includes(MODEL_AUTH_SENTINEL));
  assert.equal(capturedUrl, `${gatewayBinding.base_url}/chat/completions`);
  assert.equal(capturedByokAlias, "primary");
});

for (const retryableStatus of [401, 403, 408, 425, 429, 500, 503]) {
  test(`a managed round falls back to Unified Billing after HTTP ${retryableStatus}`, async () => {
    const calls: { url: string; headers: Headers }[] = [];
    const result = await gatewayRound(async (url, init) => {
      const headers = new Headers(init.headers);
      calls.push({ url, headers });
      if (calls.length === 1) {
        return Response.json({ error: { type: "upstream_error" } }, {
          status: retryableStatus,
          headers: { "cf-aig-log-id": `primary-${retryableStatus}` },
        });
      }
      return Response.json({
        choices: [{ message: { role: "assistant", content: "fallback" } }],
      }, { headers: { "cf-aig-log-id": `fallback-${retryableStatus}` } });
    }, "cf-gateway-token");

    assert.equal(calls.length, 2);
    assert.equal(calls[0]!.url, `${gatewayBinding.base_url}/chat/completions`);
    assert.equal(calls[0]!.headers.get("cf-aig-byok-alias"), "primary");
    assert.equal(
      calls[1]!.url,
      "https://api.cloudflare.com/client/v4/accounts/1689dd452ba2d2d8eb1f3c364c92b3f4/ai/v1/chat/completions",
    );
    assert.equal(calls[1]!.headers.get("cf-aig-gateway-id"), "gaugewright-panels");
    assert.equal(calls[1]!.headers.get("cf-aig-byok-alias"), null);
    assert.equal(calls[1]!.headers.get("authorization"), "Bearer cf-gateway-token");
    assert.equal(JSON.parse(result).status, 200);
  });
}

test("a malformed request does not spend Unified Billing as a fallback", async () => {
  let calls = 0;
  const result = await gatewayRound(async () => {
    calls += 1;
    return Response.json({ error: { type: "invalid_request_error" } }, { status: 400 });
  }, "cf-gateway-token");
  assert.equal(calls, 1);
  assert.equal(JSON.parse(result).status, 400);
});

test("a primary gateway transport failure falls back to Unified Billing", async () => {
  let calls = 0;
  const result = await gatewayRound(async (_url, _init) => {
    calls += 1;
    if (calls === 1) throw new Error("primary connection reset");
    return Response.json({
      choices: [{ message: { role: "assistant", content: "fallback" } }],
    });
  }, "cf-gateway-token");
  assert.equal(calls, 2);
  assert.equal(JSON.parse(result).status, 200);
});

test("a fallback reports both gateway rounds for cost reconciliation", async () => {
  const logIds: string[] = [];
  let calls = 0;
  await performManagedGatewayFetch(
    {
      url: `${gatewayBinding.base_url}/chat/completions`,
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
      body: { model: gatewayBinding.model },
    },
    gatewayBinding,
    { token: () => "cf-gateway-token" },
    async () => {
      calls += 1;
      return Response.json(
        calls === 1
          ? { error: { type: "rate_limit_error" } }
          : { choices: [{ message: { content: "fallback" } }] },
        {
          status: calls === 1 ? 429 : 200,
          headers: { "cf-aig-log-id": `gateway-round-${calls}` },
        },
      );
    },
    undefined,
    undefined,
    (id) => logIds.push(id),
  );
  assert.deepEqual(logIds, ["gateway-round-1", "gateway-round-2"]);
});

test("a managed gateway round publishes chat-completion text deltas", async () => {
  const deltas: string[] = [];
  const encoder = new TextEncoder();
  await performManagedGatewayFetch(
    {
      url: `${gatewayBinding.base_url}/chat/completions`,
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
      body: { model: gatewayBinding.model, stream: true },
    },
    gatewayBinding,
    { token: () => "cf-gateway-token" },
    async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(
          'data: {"choices":[{"index":0,"delta":{"content":"con"}}]}\n\n',
        ));
        controller.enqueue(encoder.encode(
          'data: {"choices":[{"index":0,"delta":{"content":"firmed"}}]}\n\n',
        ));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      },
    }), { status: 200, headers: { "content-type": "text/event-stream" } }),
    (delta) => deltas.push(delta),
  );
  assert.deepEqual(deltas, ["con", "firmed"]);
});

test("a buffered managed gateway response still publishes its assistant text", async () => {
  const deltas: string[] = [];
  await performManagedGatewayFetch(
    {
      url: `${gatewayBinding.base_url}/chat/completions`,
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
      body: { model: gatewayBinding.model, stream: false },
    },
    gatewayBinding,
    { token: () => "cf-gateway-token" },
    async () => Response.json({
      choices: [{ message: { role: "assistant", content: "confirmed" } }],
    }),
    (delta) => deltas.push(delta),
  );
  assert.deepEqual(deltas, ["confirmed"]);
});

test("a managed round refuses to run without a gateway token", async () => {
  // Must fail rather than fall back: a silent fallback bills the wrong party.
  let reached = false;
  await assert.rejects(
    () =>
      gatewayRound(async () => {
        reached = true;
        return new Response("{}", { status: 200 });
      }, undefined),
    /managed funding has no gateway token/,
  );
  assert.equal(reached, false, "no egress may happen without the token");
});

test("a managed round refuses a provider that is not the metered gateway", async () => {
  let reached = false;
  await assert.rejects(
    () =>
      performManagedGatewayFetch(
        {
          url: "https://api.openai.com/v1/responses",
          headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
          body: {},
        },
        { ...gatewayBinding, provider: "openai" as const, base_url: "https://api.openai.com" },
        { token: () => "cf-gateway-token" },
        async () => {
          reached = true;
          return new Response("{}", { status: 200 });
        },
      ),
    /requires the metered gateway/,
  );
  assert.equal(reached, false);
});

test("a managed round cannot be redirected off the admitted gateway endpoint", async () => {
  // The egress check is inherited from the direct path rather than reimplemented,
  // which is the point: this asserts the inheritance actually holds for the
  // path carrying anonymous visitors' traffic.
  let reached = false;
  await assert.rejects(
    () =>
      performManagedGatewayFetch(
        {
          url: "https://gateway.evil.example/v1/acct/gw/compat/chat/completions",
          headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
          body: {},
        },
        gatewayBinding,
        { token: () => "cf-gateway-token" },
        async () => {
          reached = true;
          return new Response("{}", { status: 200 });
        },
      ),
    /escaped the signed provider endpoint/,
  );
  assert.equal(reached, false, "no egress may reach an unadmitted origin");
});

test("managed fallback derivation refuses a non-Cloudflare compat base URL", async () => {
  let reached = false;
  await assert.rejects(
    () =>
      performManagedGatewayFetch(
        {
          url: "https://gateway.example/compat/chat/completions",
          headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
          body: {},
        },
        { ...gatewayBinding, base_url: "https://gateway.example/compat" },
        { token: () => "cf-gateway-token" },
        async () => {
          reached = true;
          return Response.json({});
        },
      ),
    /exact Cloudflare AI Gateway compat endpoint/,
  );
  assert.equal(reached, false);
});

test("the gateway log id is reported for a chat-completions round", async () => {
  // The defect this pins: the log id used to ride on a usage object parsed from
  // the response body, so a response whose usage that parser did not understand
  // produced no pointer at all — and the gateway's `/compat` surface returns
  // chat-completions, not the Responses shape it read. Every metered turn
  // silently fell back to the rate card. The log id is a fact about the round,
  // read off a header, and this is the exact body that used to defeat it.
  const logs: string[] = [];
  await performManagedGatewayFetch(
    {
      url: `${gatewayBinding.base_url}/chat/completions`,
      headers: [["authorization", `Bearer ${MODEL_AUTH_SENTINEL}`]],
      body: {},
    },
    gatewayBinding,
    { token: () => "cf-gateway-token" },
    async () =>
      new Response(
        // Chat-completions shape: real, valid, and what the old parser missed.
        JSON.stringify({ choices: [{ message: { content: "hi" } }], usage: { prompt_tokens: 8, completion_tokens: 1 } }),
        { status: 200, headers: { "content-type": "application/json", "cf-aig-log-id": "01ABCDEF" } },
      ),
    undefined,
    undefined,
    (id) => logs.push(id),
  );
  assert.deepEqual(logs, ["01ABCDEF"], "the round's cost pointer must survive");
});
