import { env } from "cloudflare:workers";
// authenticated-placement-journey
// signed-private-home-journey
// declared-route-surface
// generated-placement-boundaries
import {
  evictDurableObject,
  runDurableObjectAlarm,
  runInDurableObject,
  SELF,
} from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import {
  COLLECTION_RECIPIENT_PRIVATE_SEED_HEX,
  COLLECTION_RECIPIENT_PUBLIC_KEY_HEX,
  durableStringValues,
  nextMessage,
  openSocket,
  packageDocuments,
  sha256,
  type TestEnv,
} from "./integration-helpers";
import runtimeSurface from "../contracts/runtime-route-surface.json";

// A `:v2` attestation (DR-0063 §5): the signature covers the policy epoch and
// the authority as well, so the hosted path reads the epoch from the signature
// rather than from its caller. Regenerate with a fresh keypair rather than
// hand-editing — any edit to the body invalidates the signature.
const SIGNER = "authority:gaugedesk:test";
const PUBLIC_KEY =
  "039927e05f9269c68b201def47f7154e1092ba98bf684b272aadef5b1ac5514374";
const SIGNED_ENVELOPE =
  "{\"attestation\":{\"algorithm\":\"p256-sha256\",\"authority\":\"gaugedesk\",\"envelope_hash\":\"95aa6b54f92aed0a47c8733b848b1e25b45c5eac81b63aa394125f4064d0e1b5\",\"epoch\":1,\"key_id\":\"039927e05f9269c68b201def47f7154e1092ba98bf684b272aadef5b1ac5514374\",\"signature\":\"0d3d2ed5131334399f7e4837b99ec82ffbfb95fe0f35b04d1aca1bd9539fd5959ea16bdd5a88693b24ec9a356cd1f3867c21101ff847bf59fc1e2dcf8d9f2c74\",\"signer\":\"authority:gaugedesk:test\"},\"bindings\":{\"do\":\"placement:do\",\"model\":\"provider:openai\"},\"declassifications\":[],\"delegations\":[],\"endorsements\":[],\"parties\":{},\"placements\":{\"do\":{\"kind\":\"durable_object\",\"provider_bindings\":[\"model\"]}},\"provider_bindings\":{\"model\":{\"base_url\":\"https://api.openai.com/v1/responses\",\"credential_ref\":\"managed-openai\",\"model\":\"gpt-test\",\"provider\":\"openai\"}},\"resources\":{\"placement:do\":{\"principal\":true,\"reader\":[],\"writer\":[]},\"provider:openai\":{\"principal\":true,\"reader\":[],\"writer\":[]}}}";
const RELEASE_ID = `sha256:${"a".repeat(64)}`;
const HOST_PROTOCOL = "whipplescript.host.v1";
const POLICY_ENVELOPE = JSON.parse(SIGNED_ENVELOPE) as {
  attestation: {
    envelope_hash: string;
    key_id: string;
    signer: string;
  };
};
const POLICY_REF = {
  epoch: 1,
  envelope_hash: POLICY_ENVELOPE.attestation.envelope_hash,
  key_id: POLICY_ENVELOPE.attestation.key_id,
  signer: POLICY_ENVELOPE.attestation.signer,
};

async function bootstrapSession(
  stub: DurableObjectStub,
  sessionId: string,
  withTools = false,
  collection?: Record<string, unknown>,
): Promise<void> {
  const packageDocs = await packageDocuments(withTools);
  const bootstrap = await stub.fetch(
    "https://session.test/public/session/bootstrap",
    {
      method: "POST",
      headers: {
        authorization: "Bearer session-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        admission_scope: "theory-a-test",
        release_id: RELEASE_ID,
        session_id: sessionId,
        credential_ref:
          `credential:public:${"a".repeat(64)}:openai:${"b".repeat(32)}`,
        package_version_ref: packageDocs.version_ref,
        package: {
          manifest: packageDocs.manifest,
          source: packageDocs.source,
          system_prompt: packageDocs.system_prompt,
        },
        capabilities: withTools
          ? ["workspace.read", "workspace.write", "command.run"]
          : [],
        host_policy: {
          epoch: 1,
          signed_envelope: SIGNED_ENVELOPE,
          expected_signer: SIGNER,
          signer_public_key_hex: PUBLIC_KEY,
          provider_binding_ref: "model",
          credential_class: "managed-openai",
          placement_ref: "do",
        },
        initial_workspace: [],
        retention: {
          idle_ttl_seconds: 3600,
          absolute_ttl_seconds: 86400,
        },
        collection,
        principal: { label: "visitor" },
      }),
    },
  );
  expect(bootstrap.status, await bootstrap.clone().text()).toBe(201);
}

async function placementFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has("authorization")) {
    headers.set("authorization", "Bearer control-token");
  }
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  return SELF.fetch(
    `https://runtime.test/v1/tenants/tenant-journey/placements/placement-journey${path}`,
    { ...init, headers },
  );
}

describe("real WorkflowInstance hibernation", () => {
  it("rehydrates durable state and the browser socket attachment after object eviction", async () => {
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName("session-hibernation"));
    const packageDocs = await packageDocuments();
    const bootstrap = await stub.fetch("https://session.test/public/session/bootstrap", {
      method: "POST",
      headers: {
        authorization: "Bearer session-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        admission_scope: "theory-a-test",
        release_id: RELEASE_ID,
        session_id: "session-hibernation",
        credential_ref:
          `credential:public:${"a".repeat(64)}:openai:${"b".repeat(32)}`,
        package_version_ref: packageDocs.version_ref,
        package: {
          manifest: packageDocs.manifest,
          source: packageDocs.source,
          system_prompt: packageDocs.system_prompt,
        },
        capabilities: [],
        host_policy: {
          epoch: 1,
          signed_envelope: SIGNED_ENVELOPE,
          expected_signer: SIGNER,
          signer_public_key_hex: PUBLIC_KEY,
          provider_binding_ref: "model",
          credential_class: "managed-openai",
          placement_ref: "do",
        },
        initial_workspace: [],
        retention: {
          idle_ttl_seconds: 3600,
          absolute_ttl_seconds: 86400,
        },
        principal: { label: "visitor" },
      }),
    });
    expect(bootstrap.status, await bootstrap.clone().text()).toBe(201);

    const socket = await openSocket(stub);
    const ready = await nextMessage(socket);
    expect(ready).toMatchObject({
      type: "session_ready",
      sequence: 0,
      snapshot: {
        session_id: "session-hibernation",
        release_id: RELEASE_ID,
        cursor: 0,
      },
    });

    const claimedEvent = nextMessage(socket);
    const claim = await stub.fetch("https://session.test/public/session/claim", {
      method: "POST",
      headers: {
        authorization: "Bearer session-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ subject_hash: "b".repeat(64) }),
    });
    expect(claim.status, await claim.clone().text()).toBe(200);
    expect(await claimedEvent).toMatchObject({
      type: "session_claimed",
      sequence: 1,
    });

    await evictDurableObject(stub);
    const replayedEvent = nextMessage(socket);
    socket.send(JSON.stringify({ type: "resume", after: 0 }));
    expect(await replayedEvent).toMatchObject({
      type: "session_claimed",
      sequence: 1,
    });

    const state = await stub.fetch("https://session.test/public/session/state", {
      headers: { authorization: "Bearer session-token" },
    });
    expect(state.status).toBe(200);
    expect(await state.json()).toMatchObject({
      session_id: "session-hibernation",
      release_id: RELEASE_ID,
      cursor: 1,
    });

    socket.close(1000, "done");
    const resumedSocket = await openSocket(stub, 1);
    const resumedReady = await nextMessage(resumedSocket);
    expect(resumedReady).toMatchObject({
      type: "session_ready",
      sequence: 1,
      snapshot: {
        session_id: "session-hibernation",
        release_id: RELEASE_ID,
        cursor: 1,
      },
    });
    resumedSocket.close(1000, "done");
  });

  it("streams one direct-provider turn with canonical command correlation", async () => {
    const providerFetch = vi.fn(async (input: RequestInfo | URL) => {
      // This historical signed-policy fixture names the full Responses path;
      // production AgentRelease builders name the provider origin. The
      // correlation proof cares that the real runtime crosses its admitted
      // direct-fetch boundary, so answer the exact URL authorized by the
      // immutable fixture.
      expect(String(input)).toBe(
        "https://api.openai.com/v1/responses/v1/responses",
      );
      return new Response(
        [
          'data: {"type":"response.output_text.delta","delta":"direct"}',
          "",
          'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":2},"output_tokens":1}}}',
          "",
        ].join("\n"),
        { headers: { "content-type": "text/event-stream" } },
      );
    });
    vi.stubGlobal("fetch", providerFetch);

    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName("session-protocol"));
    await bootstrapSession(stub, "session-protocol");
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({
      type: "session_ready",
      sequence: 0,
    });

    socket.send(
      JSON.stringify({
        type: "send_message",
        request_id: "turn-1",
        text: "hello",
      }),
    );
    const observed: Record<string, unknown>[] = [];
    for (let index = 0; index < 80; index += 1) {
      const message = await nextMessage(socket);
      observed.push(message);
      if (message.type === "turn_terminal" || message.type === "error") break;
    }

    expect(observed.find(({ type }) => type === "message_accepted")).toMatchObject({
      request_id: "turn-1",
      command_id: "public:session-protocol:turn-1",
    });
    expect(observed.find(({ type }) => type === "text_delta")).toMatchObject({
      request_id: "turn-1",
      command_id: "public:session-protocol:turn-1",
      delta: "direct",
    });
    expect(
      observed
        .filter(({ type }) => type === "latency")
        .map(({ phase }) => phase),
    ).toEqual(expect.arrayContaining([
      "command_received",
      "reservation_complete",
      "direct_provider_headers",
      "direct_provider_first_body_byte",
      "direct_provider_first_text_delta",
      "websocket_first_delta_sent",
      "settlement_complete",
    ]));
    expect(observed.at(-1)).toMatchObject({
      type: "turn_terminal",
      request_id: "turn-1",
    });
    expect(JSON.stringify(observed)).not.toContain(
      "canary-provider-secret-must-not-persist",
    );
    expect((await durableStringValues(stub)).join("\n")).not.toContain(
      "canary-provider-secret-must-not-persist",
    );
    expect(providerFetch).toHaveBeenCalledOnce();
    vi.unstubAllGlobals();
    socket.close(1000, "done");
  });

  it("keeps the provider credential out of fabricated unoffered tool calls", async () => {
    const toolCalls = [
      ["write", { path: "canary.txt", content: "ordinary content" }],
      ["read", { path: "canary.txt" }],
      ["edit", {
        path: "canary.txt",
        edits: [{ oldText: "ordinary", newText: "edited" }],
      }],
      ["grep", { pattern: "edited" }],
      ["find", { pattern: "**/*.txt" }],
      ["ls", {}],
      ["recall", { id: "missing-recall-id" }],
      ["list_todos", {}],
      ["add_todo", { content: "ordinary todo" }],
      ["update_todo", { id: "missing-todo-id", status: "completed" }],
      ["bash", { command: "env" }],
    ] as const;
    let attempt = 0;
    const providerBodies: string[] = [];
    const providerFetch = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        attempt += 1;
        providerBodies.push(String(init?.body ?? ""));
        if (attempt === 1) {
          const events = toolCalls.map(([name, args], index) =>
            `data: ${JSON.stringify({
              type: "response.output_item.done",
              item: {
                type: "function_call",
                call_id: `tool-${index}`,
                name,
                arguments: JSON.stringify(args),
              },
            })}`
          );
          events.push(
            `data: ${JSON.stringify({
              type: "response.completed",
              response: {
                output: [],
                usage: {
                  input_tokens: 3,
                  input_tokens_details: { cached_tokens: 0 },
                  output_tokens: 1,
                },
              },
            })}`,
          );
          return new Response(`${events.join("\n\n")}\n\n`, {
            headers: { "content-type": "text/event-stream" },
          });
        }
        return new Response(
          [
            'data: {"type":"response.output_text.delta","delta":"tools clean"}',
            "",
            'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":0},"output_tokens":1}}}',
            "",
          ].join("\n"),
          { headers: { "content-type": "text/event-stream" } },
        );
      },
    );
    vi.stubGlobal("fetch", providerFetch);
    const logged: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((...values) => {
      logged.push(values.map(String).join(" "));
    });

    const sessionId = "session-tool-secret-canary";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({
      type: "session_ready",
      sequence: 0,
    });
    socket.send(JSON.stringify({
      type: "send_message",
      request_id: "turn-tools",
      text: "exercise tools",
    }));
    const observed: Record<string, unknown>[] = [];
    for (let index = 0; index < 160; index += 1) {
      const message = await nextMessage(socket);
      observed.push(message);
      if (message.type === "turn_terminal" || message.type === "error") break;
    }

    expect(providerFetch).toHaveBeenCalledTimes(2);
    expect(observed.some(({ type }) => type === "error")).toBe(false);
    for (const [name] of toolCalls) {
      expect(providerBodies[1], `missing ${name} result in the continued round`)
        .toContain(`"name":"${name}"`);
    }
    const allObservable = [
      JSON.stringify(observed),
      providerBodies.join("\n"),
      (await durableStringValues(stub)).join("\n"),
      logged.join("\n"),
    ].join("\n");
    expect(allObservable).not.toContain(
      "canary-provider-secret-must-not-persist",
    );
    expect(providerBodies[1]).toContain(
      "tool `bash` was not offered for this model round",
    );
    for (const forbidden of [
      "OPENAI_API_KEY",
      "ANTHROPIC_API_KEY",
    ]) {
      expect(providerBodies[1]).not.toContain(forbidden);
    }

    log.mockRestore();
    vi.unstubAllGlobals();
    socket.close(1000, "done");
  });

  it("retries an interrupted provider stream without duplicating output or settlement", async () => {
    const encoder = new TextEncoder();
    let providerAttempt = 0;
    const providerFetch = vi.fn(async () => {
      providerAttempt += 1;
      const delta =
        'data: {"type":"response.output_text.delta","delta":"once"}\n\n';
      if (providerAttempt === 1) {
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(encoder.encode(delta));
              queueMicrotask(() =>
                controller.error(new Error("injected provider disconnect")),
              );
            },
          }),
          { headers: { "content-type": "text/event-stream" } },
        );
      }
      return new Response(
        [
          delta.trimEnd(),
          'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":2},"output_tokens":1}}}',
          "",
        ].join("\n"),
        { headers: { "content-type": "text/event-stream" } },
      );
    });
    vi.stubGlobal("fetch", providerFetch);

    const sessionId = "session-provider-retry";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({
      type: "session_ready",
      sequence: 0,
    });

    socket.send(
      JSON.stringify({
        type: "send_message",
        request_id: "turn-retry",
        text: "hello",
      }),
    );
    const observed: Record<string, unknown>[] = [];
    for (let index = 0; index < 100; index += 1) {
      const message = await nextMessage(socket);
      observed.push(message);
      if (message.type === "turn_terminal" || message.type === "error") break;
    }

    expect(providerFetch).toHaveBeenCalledTimes(2);
    expect(
      observed.filter(
        ({ type, delta }) => type === "text_delta" && delta === "once",
      ),
    ).toHaveLength(1);
    expect(observed.filter(({ type }) => type === "usage")).toHaveLength(1);
    expect(observed.filter(({ type }) => type === "turn_terminal")).toHaveLength(
      1,
    );
    expect(observed.some(({ type }) => type === "error")).toBe(false);

    const deployments = (env as unknown as TestEnv).SESSION_ADMISSION;
    const deployment = deployments.get(
      deployments.idFromName("theory-a-test"),
    );
    const operations = await runInDurableObject(
      deployment,
      async (_instance, state) => ({
        admit: await state.storage.get<number>(
          `operation:${sessionId}:admit`,
        ),
        settle: await state.storage.get<number>(
          `operation:${sessionId}:settle`,
        ),
        release: await state.storage.get<number>(
          `operation:${sessionId}:release`,
        ),
      }),
    );
    expect(operations).toEqual({
      admit: 1,
      settle: 1,
      release: undefined,
    });

    vi.unstubAllGlobals();
    socket.close(1000, "done");
  });

  it("erases every durable runtime projection for a public session", async () => {
    const sessionId = "session-erasure";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({
      type: "session_ready",
      sequence: 0,
    });
    await expect(
      stub.fetch("https://session.test/public/session/claim", {
        method: "POST",
        headers: {
          authorization: "Bearer session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({ subject_hash: "e".repeat(64) }),
      }),
    ).resolves.toMatchObject({ status: 200 });
    expect((await durableStringValues(stub)).length).toBeGreaterThan(0);

    const erased = await stub.fetch(
      "https://session.test/public/session/erase",
      {
        method: "POST",
        headers: {
          authorization: "Bearer session-token",
          "content-type": "application/json",
        },
        body: "{}",
      },
    );
    expect(erased.status, await erased.clone().text()).toBe(200);
    expect(await erased.json()).toEqual({ erased: true });
    expect(await durableStringValues(stub)).toEqual([]);
    const state = await stub.fetch(
      "https://session.test/public/session/state",
      { headers: { authorization: "Bearer session-token" } },
    );
    expect(state.status, await state.clone().text()).toBe(409);
  });


  it("emits only declared paths, seals to the admitted recipient, and deposits once", async ({
    task,
  }) => {
    const sessionId = "session-collection";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    // The cross-language vector's recipient, so the Rust opener in gaugedesk can
    // decrypt what this session produces.
    const recipient = COLLECTION_RECIPIENT_PUBLIC_KEY_HEX;
    await bootstrapSession(stub, sessionId, false, {
      exportable_paths: ["responses.json"],
      transcript_eligible: false,
      schema_ref: "survey.v1",
      recipient_class: "collection:tenant",
      max_artifact_bytes: 1_000_000,
      recipient_public_keys: [recipient],
    });

    // Stand in for the interview: the agent's workspace edits, plus a file the
    // release never declared exportable.
    await runInDurableObject(stub, async (_instance, state) => {
      const session = await state.storage.get<Record<string, unknown>>(
        "public-session-state",
      );
      const instanceRef = String(session!.instance_ref);
      state.storage.sql.exec(
        "INSERT OR REPLACE INTO files (key, content) VALUES (?1, ?2)",
        `${instanceRef}/responses.json`,
        '{"q1":"collected"}',
      );
      state.storage.sql.exec(
        "INSERT OR REPLACE INTO files (key, content) VALUES (?1, ?2)",
        `${instanceRef}/private-notes.md`,
        "must not leave the session",
      );
      await state.storage.put("public-session-state", {
        ...session,
        retention: { idle_ttl_seconds: 0, absolute_ttl_seconds: 0 },
      });
    });

    expect(await runDurableObjectAlarm(stub)).toBe(true);

    const deployments = (env as unknown as TestEnv).SESSION_ADMISSION;
    const deployment = deployments.get(
      deployments.idFromName("theory-a-test"),
    );
    const held = await runInDurableObject(deployment, async (_i, state) => ({
      deposit: await state.storage.get<Record<string, unknown>>(
        `collection:${sessionId}`,
      ),
      deposits: await state.storage.get<number>(
        `operation:${sessionId}:deposit`,
      ),
    }));

    expect(held.deposits).toBe(1);
    const artifact = held.deposit!.artifact as Record<string, unknown>;
    expect(held.deposit!.idempotency_key).toBe(`${sessionId}:1`);
    expect(artifact.envelope).toMatchObject({
      schema_ref: "survey.v1",
      session_id: sessionId,
      revision: 1,
    });
    // Sealed: neither the declared answer nor the undeclared file is readable,
    // and the wrap addresses exactly the admitted recipient.
    const wire = JSON.stringify(artifact);
    expect(wire).not.toContain("collected");
    expect(wire).not.toContain("must not leave");
    expect((artifact.wraps as { recipient_public_key: string }[])[0]
      .recipient_public_key).toBe(recipient);

    // Canonical byte assembly, pinned here rather than inferred: `byte_len` is
    // the length of the artifact the DO built, and the DO built it from this
    // envelope and exactly this selected workspace. A reordering or a whitespace
    // change in `canonicalArtifact` moves this number.
    const workspace = { "responses.json": '{"q1":"collected"}' };
    const plaintext = JSON.stringify({
      envelope: artifact.envelope,
      workspace,
    });
    expect(artifact.byte_len).toBe(
      new TextEncoder().encode(plaintext).byteLength,
    );

    // Hand the emitted artifact to the Node side so `capture:collection-vector`
    // can commit it as the cross-language vector. This is what makes the vector
    // a *DO-produced* one (COLLECT-15): the previous vector came from calling
    // `sealArtifact` directly, which never exercised selection, canonical
    // assembly, the size bound, or the deposit path.
    task.meta.collectionVector = {
      note:
        "Produced by emitCollection in the Durable Object under workerd; " +
        "regenerate with `npm run capture:collection-vector` in " +
        "crates/whipplescript-host-do/worker. Rust must open it.",
      admission_scope: "theory-a-test",
      recipient_private_seed_hex: COLLECTION_RECIPIENT_PRIVATE_SEED_HEX,
      recipient_public_key_hex: recipient,
      expected_plaintext: plaintext,
      sealed: artifact,
    };

    // The session reached terminal only because the collection settled.
    const lifecycle = await runInDurableObject(stub, async (_i, state) =>
      (
        state.storage.sql
          .exec("SELECT event_json FROM session_lifecycle_events ORDER BY sequence")
          .toArray() as { event_json: string }[]
      ).map((row) => JSON.parse(row.event_json).type as string),
    );
    expect(lifecycle).toContain("collectionSettled");
    expect(lifecycle[lifecycle.length - 1]).toBe("tornDown");
  });

  it("emits an eligible empty transcript before any public event exists", async () => {
    const sessionId = "session-collection-empty-transcript";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId, false, {
      exportable_paths: [],
      transcript_eligible: true,
      schema_ref: "empty-transcript.v1",
      recipient_class: "collection:tenant",
      max_artifact_bytes: 1_000_000,
      recipient_public_keys: [COLLECTION_RECIPIENT_PUBLIC_KEY_HEX],
    });

    await runInDurableObject(stub, async (_instance, state) => {
      const session = await state.storage.get<Record<string, unknown>>(
        "public-session-state",
      );
      await state.storage.put("public-session-state", {
        ...session,
        retention: { idle_ttl_seconds: 0, absolute_ttl_seconds: 0 },
      });
    });

    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const deployments = (env as unknown as TestEnv).SESSION_ADMISSION;
    const deployment = deployments.get(
      deployments.idFromName("theory-a-test"),
    );
    const held = await runInDurableObject(deployment, async (_instance, state) =>
      state.storage.get<Record<string, unknown>>(`collection:${sessionId}`)
    );
    expect(held?.artifact).toMatchObject({
      envelope: {
        schema_ref: "empty-transcript.v1",
        session_id: sessionId,
        revision: 1,
      },
    });
  });

  it("refuses an oversized artifact definitively and deposits nothing", async () => {
    const sessionId = "session-collection-oversize";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId, false, {
      exportable_paths: ["responses.json"],
      transcript_eligible: false,
      schema_ref: "survey.v1",
      recipient_class: "collection:tenant",
      max_artifact_bytes: 512,
      recipient_public_keys: [COLLECTION_RECIPIENT_PUBLIC_KEY_HEX],
    });

    await runInDurableObject(stub, async (_instance, state) => {
      const session = await state.storage.get<Record<string, unknown>>(
        "public-session-state",
      );
      state.storage.sql.exec(
        "INSERT OR REPLACE INTO files (key, content) VALUES (?1, ?2)",
        `${String(session!.instance_ref)}/responses.json`,
        "x".repeat(4096),
      );
      await state.storage.put("public-session-state", {
        ...session,
        retention: { idle_ttl_seconds: 0, absolute_ttl_seconds: 0 },
      });
    });

    expect(await runDurableObjectAlarm(stub)).toBe(true);

    const deployments = (env as unknown as TestEnv).SESSION_ADMISSION;
    const deployment = deployments.get(
      deployments.idFromName("theory-a-test"),
    );
    const deposits = await runInDurableObject(deployment, async (_i, state) =>
      state.storage.get<number>(`operation:${sessionId}:deposit`),
    );
    // The bound is checked before sealing, so an oversized artifact never
    // reaches a recipient key and never reaches the embedder at all.
    expect(deposits).toBeUndefined();

    // Asserted on the lifecycle log rather than on `public_session_events`: the
    // narrated `collection_failed` reason is payload-adjacent and teardown
    // erases it with the rest, while the fold's own record is what survives.
    const lifecycle = await runInDurableObject(stub, async (_i, state) =>
      (
        state.storage.sql
          .exec("SELECT event_json FROM session_lifecycle_events ORDER BY sequence")
          .toArray() as { event_json: string }[]
      ).map((row) => JSON.parse(row.event_json).type as string),
    );
    // Definitive, not transient: a larger artifact will not shrink on retry, so
    // the session reaches terminal instead of retrying on every lease alarm.
    expect(lifecycle).toContain("collectionFailed");
    expect(lifecycle).not.toContain("collectionSettled");
    expect(lifecycle[lifecycle.length - 1]).toBe("tornDown");
  });

  it("expires on the retention alarm, closes transport, and erases runtime authority", async () => {
    const sessionId = "session-retention";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({
      type: "session_ready",
      sequence: 0,
    });
    const closed = new Promise<CloseEvent>((resolve) =>
      socket.addEventListener("close", resolve, { once: true }),
    );

    await runInDurableObject(stub, async (_instance, state) => {
      const session = await state.storage.get<Record<string, unknown>>(
        "public-session-state",
      );
      expect(session).toBeDefined();
      // The lease bounds are the embedder's value; the deadline is folded from
      // admitted events, so collapsing the bounds is what forces expiry now.
      await state.storage.put("public-session-state", {
        ...session,
        retention: { idle_ttl_seconds: 0, absolute_ttl_seconds: 0 },
      });
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await closed).toMatchObject({
      code: 1001,
      reason: "session expired",
    });
    // Teardown tombstones payload and preserves the audit trail (DR-0049 §7):
    // no runtime payload or credential canary survives, but the lifecycle event
    // log still shows the session opened, ran, and terminated.
    const remaining = await durableStringValues(stub);
    expect(
      remaining.some((value) => value.includes("canary-provider-secret")),
    ).toBe(false);
    expect(remaining.some((value) => value.includes('"tornDown"'))).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get("public-session-state")).toBeUndefined();
      const files = state.storage.sql
        .exec("SELECT count(*) AS total FROM files")
        .toArray() as { total: number }[];
      expect(files[0].total).toBe(0);
    });

    const state = await stub.fetch(
      "https://session.test/public/session/state",
      { headers: { authorization: "Bearer session-token" } },
    );
    expect(state.status, await state.clone().text()).toBe(409);
    const reopen = await stub.fetch(
      "https://session.test/public/session/socket",
      {
        headers: {
          authorization: "Bearer session-token",
          upgrade: "websocket",
        },
      },
    );
    expect(reopen.status, await reopen.clone().text()).toBe(409);

    const deployments = (env as unknown as TestEnv).SESSION_ADMISSION;
    const deployment = deployments.get(
      deployments.idFromName("theory-a-test"),
    );
    expect(
      await runInDurableObject(deployment, async (_instance, deploymentState) =>
        deploymentState.storage.get<number>(
          `operation:${sessionId}:expire`,
        ),
      ),
    ).toBe(1);
  });

  it("composes the authenticated placement route through the hosted protocol", async () => {
    const packageDocs = await packageDocuments();
    let brokerAttempt = 0;
    let announceCancelableRound!: () => void;
    const cancelableRoundStarted = new Promise<void>((resolve) => {
      announceCancelableRound = resolve;
    });
    let releaseCancelableRound!: () => void;
    const cancelableRoundRelease = new Promise<void>((resolve) => {
      releaseCancelableRound = resolve;
    });
    const brokerFetch = vi.fn(async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      brokerAttempt += 1;
      expect(String(input)).toBe(
        "https://model-broker.test/v1/model-egress",
      );
      expect(new Headers(init?.headers).get("authorization")).toBe(
        "Bearer model-broker-token",
      );
      const envelope = JSON.parse(String(init?.body)) as {
        protocol?: string;
        credential_ref?: string;
      };
      expect(envelope).toMatchObject({
        protocol: "whipplescript.model-egress.v1",
        credential_ref: "managed-openai",
      });
      if (brokerAttempt === 3) {
        announceCancelableRound();
        await cancelableRoundRelease;
      }
      return new Response(
        [
          'data: {"type":"response.output_text.delta","delta":"hosted"}',
          "",
          'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":1},"output_tokens":1}}}',
          "",
        ].join("\n"),
        {
          headers: {
            "x-whip-model-egress-protocol":
              "whipplescript.model-egress.stream.v1",
            "x-whip-provider-status": "200",
            "x-whip-provider-content-type": "text/event-stream",
          },
        },
      );
    });
    vi.stubGlobal("fetch", brokerFetch);

    const route =
      "https://runtime.test/v1/tenants/tenant-journey/placements/placement-journey";
    for (const authorization of [undefined, "Bearer wrong-control-token"]) {
      const denied = await SELF.fetch(`${route}/host/policy`, {
        method: "POST",
        headers: {
          ...(authorization ? { authorization } : {}),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          epoch: 1,
          signed_envelope: SIGNED_ENVELOPE,
        }),
      });
      expect(denied.status).toBe(401);
      const deniedRead = await SELF.fetch(
        `${route}/host/instances/untrusted/position`,
        {
          headers: {
            ...(authorization ? { authorization } : {}),
          },
        },
      );
      expect(deniedRead.status).toBe(401);
    }

    const policy = await placementFetch("/host/policy", {
      method: "POST",
      body: JSON.stringify({
        epoch: 1,
        signed_envelope: SIGNED_ENVELOPE,
      }),
    });
    expect(policy.status, await policy.clone().text()).toBe(201);
    expect(await policy.json()).toMatchObject({
      envelope_hash: POLICY_REF.envelope_hash,
      signer: SIGNER,
    });

    const openCommand = {
      protocol: HOST_PROTOCOL,
      request_id: "open-placement-journey",
      package_version_ref: packageDocs.version_ref,
      policy: POLICY_REF,
    };
    const openedResponse = await placementFetch("/host/instances/open", {
      method: "POST",
      body: JSON.stringify({
        command: openCommand,
        package: packageDocs,
      }),
    });
    expect(
      openedResponse.status,
      await openedResponse.clone().text(),
    ).toBe(201);
    const opened = await openedResponse.json<{
      instance_ref: string;
      opened_at: { sequence: number };
    }>();
    expect(opened.instance_ref).toBeTruthy();
    expect(opened.opened_at.sequence).toBeGreaterThan(0);
    const instancePath =
      `/host/instances/${encodeURIComponent(opened.instance_ref)}`;

    const filesSynced = await placementFetch(`${instancePath}/files/sync`, {
      method: "POST",
      body: JSON.stringify({
        files: [{ path: "journey.txt", content: "authenticated placement" }],
        delete_missing: true,
      }),
    });
    expect(filesSynced.status, await filesSynced.clone().text()).toBe(200);
    expect(await filesSynced.json()).toEqual({ synced: 1 });
    const fileList = await placementFetch(`${instancePath}/files`);
    expect(fileList.status, await fileList.clone().text()).toBe(200);
    expect(await fileList.json()).toEqual({
      files: [{ path: "journey.txt" }],
    });
    const fileRead = await placementFetch(
      `${instancePath}/files?path=journey.txt`,
    );
    expect(fileRead.status, await fileRead.clone().text()).toBe(200);
    expect(await fileRead.text()).toBe("authenticated placement");

    const eventSocketResponse = await placementFetch(
      `${instancePath}/events/live`,
      { headers: { upgrade: "websocket" } },
    );
    expect(eventSocketResponse.status).toBe(101);
    const eventSocket = eventSocketResponse.webSocket;
    expect(eventSocket).not.toBeNull();
    eventSocket!.accept();
    expect(await nextMessage(eventSocket!)).toMatchObject({
      type: "runtime_events",
    });

    const beforeTurn = await placementFetch(`${instancePath}/position`);
    expect(beforeTurn.status, await beforeTurn.clone().text()).toBe(200);
    const beforePosition = await beforeTurn.json<{
      instance_ref: string;
      sequence: number;
    }>();
    expect(beforePosition).toMatchObject({
      instance_ref: opened.instance_ref,
    });
    expect(beforePosition.sequence).toBeGreaterThan(0);

    const checkpoint = await placementFetch(`${instancePath}/checkpoint`, {
      method: "POST",
      body: JSON.stringify({ cut_id: "authenticated-journey" }),
    });
    expect(checkpoint.status, await checkpoint.clone().text()).toBe(200);
    const restore = await placementFetch(`${instancePath}/restore`, {
      method: "POST",
      body: JSON.stringify({ cut_id: "authenticated-journey" }),
    });
    expect(restore.status, await restore.clone().text()).toBe(200);

    const commandId = "turn-placement-journey";
    const turnCommand = {
      protocol: HOST_PROTOCOL,
      command_id: commandId,
      run_ref: "gaugedesk:run:placement-journey",
      instance_ref: opened.instance_ref,
      package_version_ref: packageDocs.version_ref,
      policy: POLICY_REF,
      actor_ref: "audience",
      input: { text: "hello from the placement route", images: [] },
      resources: [],
      provider_binding: {
        binding_id: "model",
        credential: { credential_id: "managed-openai" },
      },
      placement_ceiling_ref: "do",
    };
    const turn = await placementFetch("/host/turns", {
      method: "POST",
      body: JSON.stringify({
        command: turnCommand,
        package: packageDocs,
        image_bodies: [],
      }),
    });
    expect(turn.status, await turn.clone().text()).toBe(200);
    expect(await turn.json()).toMatchObject({
      admitted: true,
      command_id: commandId,
    });
    expect(brokerFetch).toHaveBeenCalledOnce();

    const turnStream = await placementFetch(
      `${instancePath}/turns/${commandId}/stream`,
    );
    expect(turnStream.status, await turnStream.clone().text()).toBe(200);
    expect(turnStream.headers.get("content-type")).toContain(
      "text/event-stream",
    );
    expect(await turnStream.text()).toContain('"delta":"hosted"');

    for (const suffix of [
      `/turns/${commandId}/result`,
      `/turns/${commandId}`,
      `/turns/${commandId}/transcript`,
      "/events",
      `/evidence?command_id=${commandId}`,
      "/pending",
    ]) {
      const projection = await placementFetch(`${instancePath}${suffix}`);
      expect(
        projection.status,
        `${suffix}: ${await projection.clone().text()}`,
      ).toBe(200);
      expect(await projection.text()).not.toContain("not found");
    }

    // DR-0068 §3: an observation surface must CARRY a pin even though it is
    // not read against one. Until 2026-08-30 the loop above only asserted 200
    // and "not not-found", so it passed against a response that gave a reader
    // no position at all — and `list_events_pinned`, implemented and tested on
    // both hosts, was reachable from nothing.
    const eventsPage = await placementFetch(`${instancePath}/events`);
    const eventsBody = (await eventsPage.json()) as {
      events: unknown[];
      position: { instance_ref: string; sequence: number; head_digest: string };
      complete: boolean;
    };
    expect(eventsBody.position.instance_ref).toBe(opened.instance_ref);
    expect(eventsBody.position.head_digest).toBeTruthy();
    expect(eventsBody.position.sequence).toBeGreaterThan(0);
    // A page that does not say it is a page reads as a complete answer.
    expect(eventsBody.complete).toBe(true);
    expect(eventsBody.events.length).toBeLessThanOrEqual(500);

    const eventStream = await placementFetch(
      `${instancePath}/events/stream?after=0`,
    );
    expect(eventStream.status, await eventStream.clone().text()).toBe(200);
    expect(eventStream.headers.get("content-type")).toContain(
      "text/event-stream",
    );
    expect(await eventStream.text()).toContain("event: runtime");

    const afterTurn = await placementFetch(`${instancePath}/position`);
    expect(afterTurn.status, await afterTurn.clone().text()).toBe(200);
    const afterPosition = await afterTurn.json<{
      instance_ref: string;
      sequence: number;
    }>();
    expect(afterPosition.sequence).toBeGreaterThan(beforePosition.sequence);
    const exportedResponse = await placementFetch(
      `${instancePath}/fork-export?sequence=${afterPosition.sequence}`,
    );
    expect(
      exportedResponse.status,
      await exportedResponse.clone().text(),
    ).toBe(200);
    const exported = await exportedResponse.json<Record<string, unknown>>();
    const rootDiscard = await placementFetch(`${instancePath}/discard`, {
      method: "POST",
      body: JSON.stringify({
        command: {
          protocol: HOST_PROTOCOL,
          request_id: "discard-root-placement-journey",
          instance_ref: opened.instance_ref,
          policy: POLICY_REF,
        },
      }),
    });
    expect(rootDiscard.status, await rootDiscard.clone().text()).toBe(409);
    expect(await rootDiscard.text()).toContain(
      "only an unadmitted host fork target can be discarded",
    );
    const forkCommand = {
      protocol: HOST_PROTOCOL,
      request_id: "fork-placement-journey",
      source: afterPosition,
      target_request_id: "open-fork-placement-journey",
      package_version_ref: packageDocs.version_ref,
      policy: POLICY_REF,
    };
    const importedResponse = await placementFetch("/host/forks/import", {
      method: "POST",
      body: JSON.stringify({
        command: forkCommand,
        export: exported,
        package: packageDocs,
      }),
    });
    expect(
      importedResponse.status,
      await importedResponse.clone().text(),
    ).toBe(201);
    const imported = await importedResponse.json<{
      target: { instance_ref: string };
    }>();
    expect(imported.target.instance_ref).not.toBe(opened.instance_ref);
    const forkPosition = await placementFetch(
      `/host/instances/${encodeURIComponent(imported.target.instance_ref)}/position`,
    );
    expect(forkPosition.status, await forkPosition.clone().text()).toBe(200);

    const discardCommand = {
      protocol: HOST_PROTOCOL,
      request_id: "discard-fork-placement-journey",
      instance_ref: imported.target.instance_ref,
      policy: POLICY_REF,
    };
    const discardPath =
      `/host/instances/${encodeURIComponent(imported.target.instance_ref)}/discard`;
    const discardedResponse = await placementFetch(discardPath, {
      method: "POST",
      body: JSON.stringify({ command: discardCommand }),
    });
    expect(
      discardedResponse.status,
      await discardedResponse.clone().text(),
    ).toBe(200);
    const discarded = await discardedResponse.json<{
      instance_ref: string;
      discarded_at: { instance_ref: string; sequence: number };
    }>();
    expect(discarded).toMatchObject({
      instance_ref: imported.target.instance_ref,
      discarded_at: { instance_ref: imported.target.instance_ref },
    });
    expect(discarded.discarded_at.sequence).toBeGreaterThan(0);
    const replayedDiscard = await placementFetch(discardPath, {
      method: "POST",
      body: JSON.stringify({ command: discardCommand }),
    });
    expect(replayedDiscard.status, await replayedDiscard.clone().text()).toBe(200);
    expect(await replayedDiscard.json()).toEqual(discarded);
    const discardedTurn = await placementFetch("/host/turns", {
      method: "POST",
      body: JSON.stringify({
        command: {
          ...turnCommand,
          command_id: "turn-discarded-fork",
          run_ref: "gaugedesk:run:discarded-fork",
          instance_ref: imported.target.instance_ref,
        },
        package: packageDocs,
        image_bodies: [],
      }),
    });
    expect(discardedTurn.status).toBe(400);

    const usedForkResponse = await placementFetch("/host/forks/import", {
      method: "POST",
      body: JSON.stringify({
        command: {
          ...forkCommand,
          request_id: "fork-used-placement-journey",
          target_request_id: "open-used-fork-placement-journey",
        },
        export: exported,
        package: packageDocs,
      }),
    });
    expect(usedForkResponse.status, await usedForkResponse.clone().text()).toBe(201);
    const usedFork = await usedForkResponse.json<{
      target: { instance_ref: string };
    }>();
    const usedForkTurn = await placementFetch("/host/turns", {
      method: "POST",
      body: JSON.stringify({
        command: {
          ...turnCommand,
          command_id: "turn-used-fork-placement-journey",
          run_ref: "gaugedesk:run:used-fork-placement-journey",
          instance_ref: usedFork.target.instance_ref,
        },
        package: packageDocs,
        image_bodies: [],
      }),
    });
    expect(usedForkTurn.status, await usedForkTurn.clone().text()).toBe(200);
    const usedForkDiscard = await placementFetch(
      `/host/instances/${encodeURIComponent(usedFork.target.instance_ref)}/discard`,
      {
        method: "POST",
        body: JSON.stringify({
          command: {
            protocol: HOST_PROTOCOL,
            request_id: "discard-used-fork-placement-journey",
            instance_ref: usedFork.target.instance_ref,
            policy: POLICY_REF,
          },
        }),
      },
    );
    expect(
      usedForkDiscard.status,
      await usedForkDiscard.clone().text(),
    ).toBe(409);
    expect(await usedForkDiscard.text()).toContain(
      "with an admitted turn cannot be discarded",
    );

    eventSocket!.close(1000, "done");
    const cancelCommandId = "turn-placement-cancel";
    const cancelableTurn = placementFetch("/host/turns", {
      method: "POST",
      body: JSON.stringify({
        command: {
          ...turnCommand,
          command_id: cancelCommandId,
          run_ref: "gaugedesk:run:placement-cancel",
          input: { text: "cancel this hosted turn", images: [] },
        },
        package: packageDocs,
        image_bodies: [],
      }),
    });
    await cancelableRoundStarted;
    const cancellation = await placementFetch(
      `${instancePath}/turns/${cancelCommandId}/cancel`,
      {
        method: "POST",
        body: "{}",
      },
    );
    expect(
      cancellation.status,
      await cancellation.clone().text(),
    ).toBe(202);
    expect(await cancellation.json()).toMatchObject({
      command_id: cancelCommandId,
      status: "requested",
    });
    releaseCancelableRound();
    const canceledTurn = await cancelableTurn;
    expect(canceledTurn.status).toBe(200);
    const canceledProjection = await placementFetch(
      `${instancePath}/turns/${cancelCommandId}`,
    );
    expect(
      canceledProjection.status,
      await canceledProjection.clone().text(),
    ).toBe(200);
    expect(await canceledProjection.json()).toMatchObject({
      command_id: cancelCommandId,
      // This policy's provider declares no native stop. The durable
      // cancellation request is accepted cooperatively, then the already
      // terminal provider response wins; the route must not falsely promise
      // that a request is an abort.
      status: "completed",
    });
    expect(brokerFetch).toHaveBeenCalledTimes(3);

    vi.unstubAllGlobals();
  });

  it("composes signed Private Home grants through the real forwarding route", async () => {
    const packageDocs = await packageDocuments();
    const fixtureResponse = await SELF.fetch(
      "https://runtime.test/__test/private-home/policy",
    );
    expect(
      fixtureResponse.status,
      await fixtureResponse.clone().text(),
    ).toBe(200);
    const fixture = await fixtureResponse.json<{
      key_id: string;
      signer: string;
      envelope_hash: string;
      governance_key_id: string;
      signed_envelope: string;
    }>();
    const homeId = "home:private-journey";
    const tenantId = "tenant:private-journey";
    const projectId = "project:private-journey";
    const commandId = "command:private-journey";
    const epoch = 1;
    const outer =
      `/v1/homes/${encodeURIComponent(homeId)}` +
      `/tenants/${encodeURIComponent(tenantId)}` +
      `/projects/${encodeURIComponent(projectId)}` +
      `/commands/${encodeURIComponent(commandId)}` +
      `/attempts/${epoch}`;

    const signedHeaders = async (
      innerPath: string,
      method: "GET" | "POST",
      body = "",
    ): Promise<Record<string, string>> => {
      const now = Math.floor(Date.now() / 1000);
      const grant = {
        version: 1,
        key_id: fixture.key_id,
        governance_signer: fixture.signer,
        home_id: homeId,
        tenant_id: tenantId,
        project_id: projectId,
        work_target_basis: "whipple:cut:private-journey",
        command_id: commandId,
        attempt_id: `attempt:${commandId}:${epoch}`,
        payload_digest: `sha256:${"1".repeat(64)}`,
        epoch,
        profile: "durable_workflow",
        package_ref: packageDocs.version_ref,
        capabilities: ["chat", "http_effect"],
        credential_class: "private-home",
        max_spend_nanos_usd: 1_000_000,
        retention_seconds: 3600,
        callback_ref:
          "https://private-home-broker.test/v1/model-egress",
        request_method: method,
        request_path: innerPath,
        request_body_sha256: await sha256(body),
        issued_at: now,
        expires_at: now + 300,
      } as const;
      const signed = await SELF.fetch(
        "https://runtime.test/__test/private-home/sign",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(grant),
        },
      );
      expect(signed.status, await signed.clone().text()).toBe(200);
      const proof = await signed.json<{
        grant: string;
        signature: string;
      }>();
      return {
        ...(method === "POST"
          ? { "content-type": "application/json" }
          : {}),
        "x-gaugewright-execution-grant": proof.grant,
        "x-gaugewright-execution-signature": proof.signature,
      };
    };
    const admitted = async (
      innerPath: string,
      method: "GET" | "POST",
      body = "",
    ): Promise<Response> =>
      SELF.fetch(`https://runtime.test${outer}${innerPath}`, {
        method,
        headers: await signedHeaders(innerPath, method, body),
        ...(method === "POST" ? { body } : {}),
      });

    const policyBody = JSON.stringify({
      epoch,
      signed_envelope: fixture.signed_envelope,
    });
    const missingGrant = await SELF.fetch(
      `https://runtime.test${outer}/host/policy`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: policyBody,
      },
    );
    expect(missingGrant.status).toBe(401);
    const tamperedHeaders = await signedHeaders(
      "/host/policy",
      "POST",
      policyBody,
    );
    const tamperedBody = await SELF.fetch(
      `https://runtime.test${outer}/host/policy`,
      {
        method: "POST",
        headers: tamperedHeaders,
        body: `${policyBody} `,
      },
    );
    expect(tamperedBody.status).toBe(403);

    const policy = await admitted(
      "/host/policy",
      "POST",
      policyBody,
    );
    expect(policy.status, await policy.clone().text()).toBe(201);
    expect(await policy.json()).toMatchObject({
      envelope_hash: fixture.envelope_hash,
      signer: fixture.signer,
    });
    const policyRef = {
      epoch,
      envelope_hash: fixture.envelope_hash,
      signer: fixture.signer,
      key_id: fixture.governance_key_id,
    };
    const openBody = JSON.stringify({
      command: {
        protocol: HOST_PROTOCOL,
        request_id: "open-private-home-journey",
        package_version_ref: packageDocs.version_ref,
        policy: policyRef,
      },
      package: packageDocs,
    });
    const open = await admitted(
      "/host/instances/open",
      "POST",
      openBody,
    );
    expect(open.status, await open.clone().text()).toBe(201);
    const opened = await open.json<{ instance_ref: string }>();
    expect(opened.instance_ref).toBeTruthy();

    const brokerFetch = vi.fn(async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      expect(String(input)).toBe(
        "https://private-home-broker.test/v1/model-egress",
      );
      const headers = new Headers(init?.headers);
      expect(headers.get("authorization")).toBeNull();
      expect(headers.get("x-gaugewright-execution-grant")).toBeTruthy();
      expect(
        headers.get("x-gaugewright-execution-signature"),
      ).toBeTruthy();
      return new Response(
        [
          'data: {"type":"response.output_text.delta","delta":"private"}',
          "",
          'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":1},"output_tokens":1}}}',
          "",
        ].join("\n"),
        {
          headers: {
            "x-whip-model-egress-protocol":
              "whipplescript.model-egress.stream.v1",
            "x-whip-provider-status": "200",
            "x-whip-provider-content-type": "text/event-stream",
          },
        },
      );
    });
    vi.stubGlobal("fetch", brokerFetch);
    const turnBody = JSON.stringify({
      command: {
        protocol: HOST_PROTOCOL,
        command_id: commandId,
        run_ref: "gaugedesk:run:private-home-journey",
        instance_ref: opened.instance_ref,
        package_version_ref: packageDocs.version_ref,
        policy: policyRef,
        actor_ref: "audience",
        input: { text: "hello from Private Home", images: [] },
        resources: [],
        provider_binding: {
          binding_id: "model",
          credential: { credential_id: "managed-openai" },
        },
        placement_ceiling_ref: "do",
      },
      package: packageDocs,
      image_bodies: [],
    });
    const turn = await admitted("/host/turns", "POST", turnBody);
    expect(turn.status, await turn.clone().text()).toBe(200);
    expect(await turn.json()).toMatchObject({
      admitted: true,
      command_id: commandId,
    });
    expect(brokerFetch).toHaveBeenCalledOnce();

    const positionPath =
      `/host/instances/${encodeURIComponent(opened.instance_ref)}/position`;
    const position = await admitted(positionPath, "GET");
    expect(position.status, await position.clone().text()).toBe(200);
    expect(await position.json()).toMatchObject({
      instance_ref: opened.instance_ref,
    });
    vi.unstubAllGlobals();
  });

  it("bounds placement identity decoding and authority across generated cases", async () => {
    const validIds = [
      "a",
      "A_1",
      "tenant:one",
      "tenant.one-1",
      "z".repeat(128),
    ];
    for (const [index, tenantId] of validIds.entries()) {
      const placementId = validIds.at(-(index + 1))!;
      const path =
        `/v1/tenants/${encodeURIComponent(tenantId)}` +
        `/placements/${encodeURIComponent(placementId)}` +
        "/host/instances/untrusted/position";
      for (const authorization of [
        undefined,
        "Bearer wrong-control-token",
      ]) {
        const denied = await SELF.fetch(`https://runtime.test${path}`, {
          headers: {
            ...(authorization ? { authorization } : {}),
          },
        });
        expect(
          denied.status,
          `${tenantId}/${placementId} admitted invalid authority`,
        ).toBe(401);
      }
    }

    const invalidSegments = [
      "%20",
      "bad%2Fvalue",
      "x".repeat(129),
      "%00",
      "%E0%A4%A",
    ];
    for (const segment of invalidSegments) {
      for (const [tenant, placement] of [
        [segment, "valid"],
        ["valid", segment],
      ]) {
        const response = await SELF.fetch(
          `https://runtime.test/v1/tenants/${tenant}/placements/${placement}/host/instances/untrusted/position`,
          {
            headers: { authorization: "Bearer control-token" },
          },
        );
        expect(
          response.status,
          `${tenant}/${placement} escaped identity validation`,
        ).toBe(400);
      }
    }

    for (const segment of ["%00", "%E0%A4%A"]) {
      const privateHome = await SELF.fetch(
        `https://runtime.test/v1/homes/${segment}/tenants/valid/projects/valid/commands/valid/attempts/1/host/instances/untrusted/position`,
      );
      expect(
        privateHome.status,
        `${segment} crashed the Private Home identity decoder`,
      ).not.toBe(500);
      if (segment === "%E0%A4%A") {
        expect(privateHome.status).toBe(404);
      }
    }
  });

  it("rejects invalid authority and accepts every declared inner route method", async () => {
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName("declared-route-surface"));
    const operations = runtimeSurface.operations.filter(({ path }) =>
      path === "/start"
      || path.startsWith("/host/")
      || path.startsWith("/public/session/")
    );
    expect(operations.length).toBe(28);

    for (const operation of operations) {
      for (const authorization of [undefined, "Bearer wrong-control-token"]) {
        const denied = await stub.fetch(
          `https://runtime.test${operation.samplePath}`,
          {
            method: operation.method,
            headers: {
              ...(authorization ? { authorization } : {}),
              ...(operation.method === "POST"
                ? { "content-type": "application/json" }
                : {}),
            },
            ...(operation.method === "POST" ? { body: "{}" } : {}),
          },
        );
        expect(
          denied.status,
          `${operation.method} ${operation.path} admitted invalid authority`,
        ).toBe(401);
      }
      const response = await stub.fetch(
        `https://runtime.test${operation.samplePath}`,
        {
          method: operation.method,
          headers: {
            authorization: operation.path.startsWith("/public/session/")
              ? "Bearer session-token"
              : "Bearer control-token",
            ...(operation.method === "POST"
              ? { "content-type": "application/json" }
              : {}),
          },
          ...(operation.method === "POST" ? { body: "{}" } : {}),
        },
      );
      expect(
        response.status,
        `${operation.method} ${operation.path} rejected its declared method`,
      ).not.toBe(405);
      await response.body?.cancel();
    }
  });

  it("keeps session state, events, and sockets isolated by object identity", async () => {
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const first = namespace.get(namespace.idFromName("session-isolation-a"));
    const second = namespace.get(namespace.idFromName("session-isolation-b"));
    await bootstrapSession(first, "session-isolation-a");
    await bootstrapSession(second, "session-isolation-b");

    const firstSocket = await openSocket(first);
    expect(await nextMessage(firstSocket)).toMatchObject({
      type: "session_ready",
      sequence: 0,
      snapshot: { session_id: "session-isolation-a" },
    });
    const secondSocket = await openSocket(second);
    expect(await nextMessage(secondSocket)).toMatchObject({
      type: "session_ready",
      sequence: 0,
      snapshot: { session_id: "session-isolation-b" },
    });

    const leakedToSecond: Record<string, unknown>[] = [];
    secondSocket.addEventListener("message", (event) => {
      leakedToSecond.push(
        JSON.parse(String(event.data)) as Record<string, unknown>,
      );
    });
    const firstClaimed = nextMessage(firstSocket);
    const claim = await first.fetch("https://session.test/public/session/claim", {
      method: "POST",
      headers: {
        authorization: "Bearer session-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ subject_hash: "c".repeat(64) }),
    });
    expect(claim.status).toBe(200);
    expect(await firstClaimed).toMatchObject({
      type: "session_claimed",
      sequence: 1,
    });
    await Promise.resolve();
    expect(leakedToSecond).toEqual([]);

    const firstState = await (
      await first.fetch("https://session.test/public/session/state", {
        headers: { authorization: "Bearer session-token" },
      })
    ).json<Record<string, unknown>>();
    const secondState = await (
      await second.fetch("https://session.test/public/session/state", {
        headers: { authorization: "Bearer session-token" },
      })
    ).json<Record<string, unknown>>();
    expect(firstState).toMatchObject({
      session_id: "session-isolation-a",
      cursor: 1,
    });
    expect(secondState).toMatchObject({
      session_id: "session-isolation-b",
      cursor: 0,
    });
    expect((await durableStringValues(first)).join("\n")).not.toContain(
      "session-isolation-b",
    );
    expect((await durableStringValues(second)).join("\n")).not.toContain(
      "session-isolation-a",
    );
    firstSocket.close(1000, "done");
    secondSocket.close(1000, "done");
  });
});
