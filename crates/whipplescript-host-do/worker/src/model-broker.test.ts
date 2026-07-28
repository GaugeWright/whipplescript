import assert from "node:assert/strict";
import test from "node:test";
import {
  performDirectProviderFetch,
  MODEL_AUTH_SENTINEL,
  MODEL_EGRESS_PROTOCOL,
  MODEL_EGRESS_STREAM_PROTOCOL,
  performModelBrokerFetch,
  stripSentinelAuthentication,
} from "./model-broker.ts";

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
  let usage:
    | {
        input_tokens: number;
        cached_input_tokens: number;
        output_tokens: number;
      }
    | undefined;
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
    (observed) => {
      usage = observed;
    },
  );
  assert.equal(capturedAuthorization, "Bearer sk-session-secret");
  assert.deepEqual(deltas, ["direct"]);
  assert.deepEqual(usage, {
    input_tokens: 3,
    cached_input_tokens: 2,
    output_tokens: 1,
  });
  assert.deepEqual(timing, [
    "direct_provider_fetch_start",
    "direct_provider_headers",
    "direct_provider_first_body_byte",
    "direct_provider_first_text_delta",
    "direct_provider_body_complete",
  ]);
  assert.equal(JSON.parse(result).status, 200);
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
    /token is unavailable/,
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
