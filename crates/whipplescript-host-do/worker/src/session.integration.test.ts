import { env } from "cloudflare:workers";
// workerd-production-object
// session-control-boundary
import {
  evictDurableObject,
  runDurableObjectAlarm,
  runInDurableObject,
} from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, sha256Hex } from "./private-home-protocol";

const SIGNER = "authority:gaugedesk:test";
const PUBLIC_KEY =
  "031e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e";
const SIGNED_ENVELOPE =
  "{\"attestation\":{\"algorithm\":\"p256-sha256\",\"envelope_hash\":\"82abb646568a06e56ecfc32f6352c2bfd3e532f1c78b2ebb7541cc0c8c59e2d4\",\"key_id\":\"031e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e\",\"signature\":\"1fcf647b38a03a3aeccb38a05f4f55ca70db1e7f88cc6fc25f826fbc20a109a64587e2f27a498f466735d7d4da7c33d6e5ec2ac9ece4a31f0690805df2673fe5\",\"signer\":\"authority:gaugedesk:test\"},\"bindings\":{\"do\":\"placement:do\",\"model\":\"provider:openai\",\"turn_images\":\"memory:turn-images\"},\"declassifications\":[],\"delegations\":[],\"endorsements\":[],\"parties\":{\"audience\":\"audience\"},\"placements\":{\"do\":{\"kind\":\"durable_object\",\"provider_bindings\":[\"model\"]}},\"provider_bindings\":{\"model\":{\"base_url\":\"https://api.openai.com/v1/responses\",\"credential_ref\":\"managed-openai\",\"model\":\"gpt-test\",\"provider\":\"openai\"}},\"resources\":{\"memory:turn-images\":{\"reader\":[\"audience\"],\"writer\":[\"audience\"]},\"placement:do\":{\"principal\":true,\"reader\":[],\"writer\":[]},\"provider:openai\":{\"principal\":true,\"reader\":[],\"writer\":[]}}}";
const RELEASE_ID = `sha256:${"a".repeat(64)}`;

// The collection recipient the cross-language vector is addressed to. A test
// keypair with no production standing: the private half is here precisely so the
// captured vector can be opened, and the sealer never sees it — the DO is handed
// the public half alone, exactly as a tenant's release declares it.
const COLLECTION_RECIPIENT_PRIVATE_SEED_HEX =
  "624b847dff874876d18980a7d12c116f4848421302e09569efb3fa62cca47b85";
const COLLECTION_RECIPIENT_PUBLIC_KEY_HEX =
  "04e98c4b5e749038c87fb11e238ea748e0e7b3c952d91e909dbf22084afe86fc4d28dbedee9b3449323fdf6ebaa02810666ed917e4a6dc0b70725bcbff0438d1a0";

type TestEnv = {
  WORKFLOW_INSTANCE: DurableObjectNamespace;
  SESSION_ADMISSION: DurableObjectNamespace;
};

function hex(bytes: Uint8Array): string {
  return [...bytes]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(value: string): Promise<string> {
  return hex(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  );
}

/**
 * Mint a signed governance envelope in-process.
 *
 * The suite previously carried one hard-coded envelope, and it grants no
 * workspace capabilities — so every tool a test asked for was refused before
 * dispatch and no test could drive a tool-USING turn. That is the gap the
 * durable-assistant regression walked through: `assistant_text` is only left
 * empty when a turn's last assistant message carried tool calls, which is the
 * one shape the suite could not express.
 */
async function mintSignedEnvelope(
  capabilities: string[] = [],
  extra: { bindings?: Record<string, string>; resources?: Record<string, unknown> } = {},
) {
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const point = (value: string) =>
    Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const publicKeyHex = `04${[...point(jwk.x!), ...point(jwk.y!)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
  const signer = "authority:gaugedesk:test";

  const unsigned = {
    bindings: {
      do: "placement:do",
      model: "provider:openai",
      turn_images: "memory:turn-images",
      ...extra.bindings,
    },
    // The epoch's capability ceiling: a package may request nothing outside it.
    // Sorted: the verifier re-canonicalizes through a BTreeSet, so an
    // insertion-ordered array hashes to a different envelope than the one it
    // checks the attestation against.
    ...(capabilities.length > 0 ? { capabilities: [...capabilities].sort() } : {}),
    declassifications: [],
    delegations: [],
    endorsements: [],
    parties: { audience: "audience" },
    placements: { do: { kind: "durable_object", provider_bindings: ["model"] } },
    provider_bindings: {
      model: {
        base_url: "https://api.openai.com/v1/responses",
        credential_ref: "managed-openai",
        model: "gpt-test",
        provider: "openai",
      },
    },
    resources: {
      "memory:turn-images": { reader: ["audience"], writer: ["audience"] },
      "placement:do": { principal: true, reader: [], writer: [] },
      "provider:openai": { principal: true, reader: [], writer: [] },
      ...extra.resources,
    },
  };
  const canonical = canonicalJson(unsigned);
  const envelopeHash = await sha256Hex(new TextEncoder().encode(canonical));
  // The governance signing preimage: a domain tag then each field
  // length-prefixed, so no two field splits can collide.
  let preimage = "whipplescript-governance-envelope:v1;";
  for (const item of [envelopeHash, signer, "p256-sha256", publicKeyHex]) {
    preimage += `${new TextEncoder().encode(item).byteLength}:${item};`;
  }
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keys.privateKey,
    new TextEncoder().encode(preimage),
  );
  const signatureHex = [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return {
    publicKeyHex,
    signer,
    text: canonicalJson({
      ...unsigned,
      attestation: {
        algorithm: "p256-sha256",
        envelope_hash: envelopeHash,
        key_id: publicKeyHex,
        signature: signatureHex,
        signer,
      },
    }),
  };
}

async function packageDocuments(withTools = false) {
  const capabilities = withTools
    ? ["workspace.read", "workspace.write", "command.run"]
    : [];
  const source = withTools
    ? `file store project { root "." allow read ["**"] allow write ["**"] }
workflow Published {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
    capabilities ["workspace.read", "workspace.write", "command.run"]
  }
  rule converse when started => {
    tell assistant requires ["workspace.read", "workspace.write", "command.run"]
      with access to project { read ["**"] write ["**"] }
      with access to command { run }
      "Exercise the admitted tools."
  }
}`
    : `workflow Published {
  agent assistant {
    provider owned
    profile "repo-reader"
    capacity 1
    capabilities []
  }
  rule converse when started => {
    tell assistant "Answer without tools."
  }
}`;
  const manifest = JSON.stringify({
    schema: "whipplescript.agent_package.v0",
    source: "agent.whip",
    workflow: "Published",
    agent: "assistant",
    system_prompt: "persona.md",
    capabilities,
    agent_abilities: capabilities,
    max_steps: 8,
  });
  const system_prompt = "Be helpful.";
  const version = await sha256(
    JSON.stringify({ manifest, source, system_prompt }),
  );
  return {
    manifest,
    source,
    system_prompt,
    version_ref: `whip:agent-package:${version}`,
  };
}

function nextMessage(socket: WebSocket): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const onMessage = (event: MessageEvent) => {
      cleanup();
      resolve(JSON.parse(String(event.data)) as Record<string, unknown>);
    };
    const onError = () => {
      cleanup();
      reject(new Error("websocket failed"));
    };
    const cleanup = () => {
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("error", onError);
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("error", onError);
  });
}

async function openSocket(
  stub: DurableObjectStub,
  after = 0,
): Promise<WebSocket> {
  const response = await stub.fetch(
    new Request(
      `https://session.test/public/session/socket${after ? `?after=${after}` : ""}`,
      {
        headers: {
          authorization: "Bearer session-token",
          upgrade: "websocket",
        },
      },
    ),
  );
  expect(response.status).toBe(101);
  const socket = response.webSocket;
  expect(socket).not.toBeNull();
  socket!.accept();
  return socket!;
}

async function bootstrapSession(
  stub: DurableObjectStub,
  sessionId: string,
  withTools = false,
  collection?: Record<string, unknown>,
  envelope?: { text: string; signer: string; publicKeyHex: string },
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
          signed_envelope: envelope?.text ?? SIGNED_ENVELOPE,
          expected_signer: envelope?.signer ?? SIGNER,
          signer_public_key_hex: envelope?.publicKeyHex ?? PUBLIC_KEY,
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

async function durableStringValues(stub: DurableObjectStub): Promise<string[]> {
  return runInDurableObject(stub, async (_instance, state) => {
    const values = [...(await state.storage.list()).values()].map((value) =>
      JSON.stringify(value),
    );
    const tables = state.storage.sql
      .exec(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '_cf_*'",
      )
      .toArray() as { name: string; sql: string }[];
    for (const { name, sql } of tables) {
      const table = `"${name.replaceAll('"', '""')}"`;
      const columns: string[] = [];
      const body = sql.slice(sql.indexOf("(") + 1, sql.lastIndexOf(")"));
      let start = 0;
      let depth = 0;
      for (let index = 0; index <= body.length; index += 1) {
        const character = body[index];
        if (character === "(") depth += 1;
        if (character === ")") depth -= 1;
        if ((character === "," && depth === 0) || index === body.length) {
          const definition = body.slice(start, index).trim();
          start = index + 1;
          const match = /^"?([A-Za-z_][A-Za-z0-9_]*)"?\s+/.exec(definition);
          const candidate = match?.[1];
          if (
            candidate &&
            !["constraint", "primary", "unique", "foreign", "check"].includes(
              candidate.toLowerCase(),
            )
          ) {
            columns.push(candidate);
          }
        }
      }
      for (const column of columns) {
        const field = `"${column.replaceAll('"', '""')}"`;
        const rows = state.storage.sql
          .exec(
            `SELECT CAST(${field} AS TEXT) AS value FROM ${table} WHERE ${field} IS NOT NULL`,
          )
          .toArray() as { value: string }[];
        values.push(...rows.map(({ value }) => value));
      }
    }
    return values;
  });
}

describe("real WorkflowInstance hibernation", () => {
  it("does not echo a browser's reserved no-status close code", async () => {
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName("session-browser-close-without-status"));
    await runInDurableObject(stub, async (instance) => {
      let echoed = false;
      const observed = instance as unknown as {
        webSocketClose: (socket: WebSocket, code: number, reason: string) => void;
      };
      observed.webSocketClose({
        close() { echoed = true; },
      } as unknown as WebSocket, 1005, "");
      expect(echoed).toBe(false);
    });
  });

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

  it("streams one direct-provider image turn with canonical command correlation", async () => {
    const providerFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      // This historical signed-policy fixture names the full Responses path;
      // production AgentRelease builders name the provider origin. The
      // correlation proof cares that the real runtime crosses its admitted
      // direct-fetch boundary, so answer the exact URL authorized by the
      // immutable fixture.
      expect(String(input)).toBe(
        "https://api.openai.com/v1/responses/v1/responses",
      );
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(JSON.stringify(body)).toContain(
        '"image_url":"data:image/png;base64,aGVsbG8="',
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
        images: [{ media_type: "image/png", data_base64: "aGVsbG8=" }],
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

  it("applies durable steering before the next model round and follow-up at idle", async () => {
    let releaseFirst!: () => void;
    const firstRoundGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const providerBodies: string[] = [];
    let round = 0;
    const providerFetch = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        round += 1;
        providerBodies.push(String(init?.body ?? ""));
        if (round === 1) {
          await firstRoundGate;
          return new Response(
            [
              `data: ${JSON.stringify({
                type: "response.output_item.done",
                item: {
                  type: "function_call",
                  call_id: "tool-1",
                  name: "read",
                  arguments: JSON.stringify({ path: "README.md" }),
                },
              })}`,
              `data: ${JSON.stringify({
                type: "response.completed",
                response: {
                  output: [],
                  usage: { input_tokens: 3, output_tokens: 1 },
                },
              })}`,
              "",
            ].join("\n"),
            { headers: { "content-type": "text/event-stream" } },
          );
        }
        const text = round === 2 ? "redirected" : "followed up";
        return new Response(
          [
            `data: ${JSON.stringify({ type: "response.output_text.delta", delta: text })}`,
            `data: ${JSON.stringify({
              type: "response.completed",
              response: {
                output: [],
                usage: { input_tokens: 3, output_tokens: 1 },
              },
            })}`,
            "",
          ].join("\n"),
          { headers: { "content-type": "text/event-stream" } },
        );
      },
    );
    vi.stubGlobal("fetch", providerFetch);

    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName("session-interactive-commands"));
    await bootstrapSession(stub, "session-interactive-commands");
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({ type: "session_ready" });
    socket.send(JSON.stringify({
      type: "send_message",
      request_id: "turn-live",
      text: "start",
    }));
    await vi.waitFor(() => expect(providerFetch).toHaveBeenCalledTimes(1));
    socket.send(JSON.stringify({
      type: "follow_up",
      operation_id: "op-follow",
      request_id: "follow-1",
      text: "one more thing",
    }));
    socket.send(JSON.stringify({
      type: "steer",
      operation_id: "op-steer",
      request_id: "steer-1",
      text: "change direction",
    }));

    const observed: Record<string, unknown>[] = [];
    while (
      observed.filter(({ type }) => type === "turn_queue_changed").length < 2
    ) {
      observed.push(await nextMessage(socket));
    }
    releaseFirst();
    for (let index = 0; index < 120; index += 1) {
      const message = await nextMessage(socket);
      observed.push(message);
      if (message.type === "turn_terminal" || message.type === "error") break;
    }

    expect(providerFetch).toHaveBeenCalledTimes(3);
    expect(providerBodies[1]).toContain("change direction");
    expect(providerBodies[2]).toContain("one more thing");
    expect(observed.filter(({ type }) => type === "turn_command_applied"))
      .toEqual(expect.arrayContaining([
        expect.objectContaining({ request_id: "steer-1", kind: "steer" }),
        expect.objectContaining({ request_id: "follow-1", kind: "follow_up" }),
      ]));
    expect(observed.at(-1)).toMatchObject({
      type: "turn_terminal",
      request_id: "turn-live",
    });
    const state = await stub.fetch("https://session.test/public/session/state", {
      headers: { authorization: "Bearer session-token" },
    });
    expect(await state.json()).toMatchObject({
      queue: [],
      transcript: [
        { type: "user", text: "start" },
        { type: "user", text: "change direction" },
        { type: "assistant", text: "redirected" },
        { type: "user", text: "one more thing" },
        { type: "assistant", text: "followed up" },
      ],
    });
    vi.unstubAllGlobals();
    socket.close(1000, "done");
  });

  it("stops cooperatively at the next model boundary without starting another round", async () => {
    let releaseFirst!: () => void;
    const firstRoundGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const providerFetch = vi.fn(
      async () => {
        await firstRoundGate;
        return new Response(
          [
            `data: ${JSON.stringify({
              type: "response.output_item.done",
              item: {
                type: "function_call",
                call_id: "tool-cancel",
                name: "read",
                arguments: JSON.stringify({ path: "README.md" }),
              },
            })}`,
            `data: ${JSON.stringify({
              type: "response.completed",
              response: {
                output: [],
                usage: { input_tokens: 3, output_tokens: 1 },
              },
            })}`,
            "",
          ].join("\n"),
          { headers: { "content-type": "text/event-stream" } },
        );
      },
    );
    vi.stubGlobal("fetch", providerFetch);

    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName("session-cooperative-stop"));
    await bootstrapSession(stub, "session-cooperative-stop");
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({ type: "session_ready" });
    socket.send(JSON.stringify({
      type: "send_message",
      request_id: "turn-stop",
      text: "start",
    }));
    await vi.waitFor(() => expect(providerFetch).toHaveBeenCalledOnce());
    socket.send(JSON.stringify({ type: "stop", request_id: "turn-stop" }));

    const observed: Record<string, unknown>[] = [];
    while (!observed.some(({ type }) => type === "turn_stop_requested")) {
      observed.push(await nextMessage(socket));
    }
    releaseFirst();
    for (let index = 0; index < 80; index += 1) {
      const message = await nextMessage(socket);
      observed.push(message);
      if (message.type === "turn_terminal" || message.type === "error") break;
    }

    expect(providerFetch).toHaveBeenCalledOnce();
    expect(observed.at(-1)).toMatchObject({
      type: "turn_terminal",
      request_id: "turn-stop",
      status: 200,
      body: { outcome: "interrupted" },
    });
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

  it("re-arms collection when a request first observes expiry", async () => {
    const sessionId = "session-request-observed-expiry";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId, false, {
      exportable_paths: [],
      transcript_eligible: true,
      schema_ref: "survey.v1",
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
      await state.storage.deleteAlarm();
      expect(await state.storage.getAlarm()).toBeNull();
    });

    const observed = await stub.fetch("https://session.test/public/session/state", {
      headers: { authorization: "Bearer session-token" },
    });
    expect(observed.status, await observed.clone().text()).toBe(410);
    expect(await runInDurableObject(stub, async (_instance, state) =>
      state.storage.getAlarm()
    )).not.toBeNull();
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    const deployments = (env as unknown as TestEnv).SESSION_ADMISSION;
    const deployment = deployments.get(deployments.idFromName("theory-a-test"));
    expect(await runInDurableObject(deployment, async (_instance, state) =>
      state.storage.get<number>(`operation:${sessionId}:deposit`)
    )).toBe(1);
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

  it("schedules the retention alarm at bootstrap so expiry needs no visitor", async () => {
    // Every other retention test collapses the TTLs and calls
    // `runDurableObjectAlarm` by hand, which proves what the handler does once
    // it runs and says nothing about whether anything ever runs it. In
    // production nothing did: sessions sat past their absolute deadline,
    // unexpired, and a declared collection stayed pending forever because the
    // only path that emits it is the alarm.
    const sessionId = "session-alarm-scheduled";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    const before = Date.now();
    await bootstrapSession(stub, sessionId);

    const scheduled = await runInDurableObject(stub, async (_instance, state) =>
      state.storage.getAlarm(),
    );
    expect(scheduled, "bootstrap must arm the retention alarm").not.toBeNull();
    // `bootstrapSession` declares idle 3600s / absolute 86400s, so the idle
    // bound is the earlier one and the deadline is openedAt + 3600s.
    const idleMs = 3600 * 1000;
    expect(scheduled!).toBeGreaterThanOrEqual(before + idleMs);
    expect(scheduled!).toBeLessThanOrEqual(Date.now() + idleMs);
  });

  it("keeps the retention alarm armed after a turn drives the instance", async () => {
    // The defect this pins: the object has one alarm and two schedulers for it.
    // Driving the instance used to `deleteAlarm()` whenever it parked with
    // nothing due, and driving is the last thing a turn does — so every turn
    // disarmed retention. Sessions that ran a turn never expired, and because
    // the expiry alarm is the only path that emits a declared collection, the
    // drain stayed empty forever while everything else looked healthy.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          [
            'data: {"type":"response.output_text.delta","delta":"ok"}',
            "",
            'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":2},"output_tokens":1}}}',
            "",
          ].join("\n"),
          { headers: { "content-type": "text/event-stream" } },
        ),
      ),
    );

    const sessionId = "session-alarm-survives-turn";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    const armedAtBootstrap = await runInDurableObject(
      stub,
      async (_instance, state) => state.storage.getAlarm(),
    );
    expect(armedAtBootstrap).not.toBeNull();

    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({ type: "session_ready" });
    socket.send(
      JSON.stringify({
        type: "send_message",
        request_id: "turn-alarm-1",
        text: "hello",
      }),
    );
    for (let index = 0; index < 80; index += 1) {
      const message = await nextMessage(socket);
      if (message.type === "turn_terminal" || message.type === "error") break;
    }

    const armedAfterTurn = await runInDurableObject(
      stub,
      async (_instance, state) => state.storage.getAlarm(),
    );
    expect(
      armedAfterTurn,
      "a turn must not disarm the session's retention deadline",
    ).not.toBeNull();
  });

  it("normalizes a legacy session record and backfills its lifecycle (DR-0054)", async () => {
    // The pre-DR-0049 shape: a session record without `retention`/`principal`
    // and no lifecycle log. Reading it used to throw a raw TypeError (killing
    // `alarm()` permanently), and the empty log folded to `init`, which
    // refuses deadline observations — an immortal session.
    const sessionId = "session-legacy-shape";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec("DELETE FROM session_lifecycle_events");
      const session = (await state.storage.get<Record<string, unknown>>(
        "public-session-state",
      ))!;
      delete session.retention;
      delete session.principal;
      await state.storage.put("public-session-state", session);
    });

    const response = await stub.fetch(
      "https://session.test/public/session/state",
      { headers: { authorization: "Bearer session-token" } },
    );
    expect(response.status, await response.clone().text()).toBe(200);

    // The read normalized the record (compat defaults, nothing deleted) and
    // backfilled the lifecycle log so a retention deadline now exists.
    await runInDurableObject(stub, async (_instance, state) => {
      const events = (
        state.storage.sql
          .exec("SELECT event_json FROM session_lifecycle_events ORDER BY sequence")
          .toArray() as { event_json: string }[]
      ).map((row) => JSON.parse(row.event_json) as { type: string });
      expect(events.map((event) => event.type)).toEqual(
        expect.arrayContaining(["opened", "activated"]),
      );
      expect(await state.storage.get("public-session-state")).toBeDefined();
    });
  });

  it("expires a pre-lifecycle session through the governed path (DR-0054)", async () => {
    const sessionId = "session-legacy-expiry";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    await runInDurableObject(stub, async (_instance, state) => {
      // Regress to a legacy object whose recorded bounds have long passed.
      state.storage.sql.exec("DELETE FROM session_lifecycle_events");
      const session = (await state.storage.get<Record<string, unknown>>(
        "public-session-state",
      ))!;
      await state.storage.put("public-session-state", {
        ...session,
        created_at_unix_ms: Date.now() - 60_000,
        last_activity_unix_ms: Date.now() - 60_000,
        retention: { idle_ttl_seconds: 1, absolute_ttl_seconds: 1 },
      });
    });

    // The alarm backfills the log from the record's own attested times, folds
    // the deadline observation, and tears the session down — the legacy
    // session is expirable, not immortal.
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const remaining = await durableStringValues(stub);
    expect(remaining.some((value) => value.includes('"tornDown"'))).toBe(true);
    const state = await stub.fetch(
      "https://session.test/public/session/state",
      { headers: { authorization: "Bearer session-token" } },
    );
    expect(state.status, await state.clone().text()).toBe(409);
  });

  it("fails closed on an unknown lifecycle event without erasing anything (DR-0054)", async () => {
    // The rollback shape: a newer worker appended an event this build does not
    // know. The fold used to reduce it to `undefined` and poison every state
    // after it; now readers refuse with a diagnosable error, the alarm keeps
    // retrying instead of dying, and nothing is deleted.
    const sessionId = "session-unknown-event";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO session_lifecycle_events (event_json) VALUES (?1)",
        JSON.stringify({ type: "leaseExtended", atMs: Date.now() }),
      );
    });

    const response = await stub.fetch(
      "https://session.test/public/session/state",
      { headers: { authorization: "Bearer session-token" } },
    );
    expect(response.status).toBe(500);
    expect(await response.text()).toContain("leaseExtended");

    // The alarm handler survives, re-arms itself, and deletes nothing.
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get("public-session-state")).toBeDefined();
      expect(await state.storage.getAlarm()).not.toBeNull();
      const log = state.storage.sql
        .exec("SELECT count(*) AS total FROM session_lifecycle_events")
        .toArray() as { total: number }[];
      expect(log[0].total).toBeGreaterThan(0);
    });
  });

  it("tombstones the instance projections coherently at expiry (DR-0054)", async () => {
    const sessionId = "session-tombstone-coherence";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    await runInDurableObject(stub, async (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT status FROM instances")
        .toArray() as { status: string }[];
      expect(rows.length).toBeGreaterThan(0);
      const session = await state.storage.get<Record<string, unknown>>(
        "public-session-state",
      );
      await state.storage.put("public-session-state", {
        ...session,
        retention: { idle_ttl_seconds: 0, absolute_ttl_seconds: 0 },
      });
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    await runInDurableObject(stub, async (_instance, state) => {
      // Canonical events/facts are tombstoned...
      const events = state.storage.sql
        .exec("SELECT count(*) AS total FROM events")
        .toArray() as { total: number }[];
      expect(events[0].total).toBe(0);
      // ...and no projection row still claims to be live: a rebuild cannot
      // fold zero events over a "running" instance.
      for (const [table, live] of [
        ["instances", "'running'"],
        ["effects", "'queued', 'running'"],
        ["runs", "'running'"],
      ] as const) {
        const rows = state.storage.sql
          .exec(`SELECT count(*) AS total FROM ${table} WHERE status IN (${live})`)
          .toArray() as { total: number }[];
        expect(rows[0].total, `${table} must hold no live rows`).toBe(0);
      }
      const tombstoned = state.storage.sql
        .exec("SELECT count(*) AS total FROM instances WHERE status = 'tombstoned'")
        .toArray() as { total: number }[];
      expect(tombstoned[0].total).toBeGreaterThan(0);
      // The explicit audit marker survives in the retained diagnostics table.
      const marker = state.storage.sql
        .exec(
          "SELECT count(*) AS total FROM diagnostics WHERE code = 'session.tombstoned'",
        )
        .toArray() as { total: number }[];
      expect(marker[0].total).toBe(1);
    });
  });

  it("lazily provisions the tracker tables on an existing object (DR-0054)", async () => {
    // A deployed object was created before `tracker_aliases` /
    // `tracker_comments` / `tracker_evidence` and the content-addressed
    // `tracker_events` columns existed, and the first-touch schema never
    // revisits an existing object — production tracker reads failed on it.
    const sessionId = "session-tracker-upgrade";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    await runInDurableObject(stub, async (_instance, state) => {
      // Regress the object to the pre-ADR-0002 tracker shape.
      state.storage.sql.exec("DROP INDEX idx_tracker_events_id");
      state.storage.sql.exec("ALTER TABLE tracker_events DROP COLUMN event_id");
      state.storage.sql.exec("ALTER TABLE tracker_events DROP COLUMN parents_json");
      state.storage.sql.exec("DROP TABLE tracker_aliases");
      state.storage.sql.exec("DROP TABLE tracker_comments");
      state.storage.sql.exec("DROP TABLE tracker_evidence");
    });

    // Any entry that touches the schema upgrades the object in place.
    const response = await stub.fetch(
      "https://session.test/public/session/state",
      { headers: { authorization: "Bearer session-token" } },
    );
    expect(response.status, await response.clone().text()).toBe(200);

    await runInDurableObject(stub, async (_instance, state) => {
      for (const table of [
        "tracker_aliases",
        "tracker_comments",
        "tracker_evidence",
      ]) {
        const present = state.storage.sql
          .exec(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
            table,
          )
          .toArray();
        expect(present.length, `${table} must exist after upgrade`).toBe(1);
      }
      // The content-addressed columns and their dedup index are back too:
      // the production append shape works, and repeating it is a no-op.
      const insert = () =>
        state.storage.sql.exec(
          `INSERT OR IGNORE INTO tracker_events
             (event_id, parents_json, issue_id, kind, payload_json, actor, created_at)
           VALUES ('ev-upgrade', '[]', 'content-1', 'issue.created', '{}', 'tester', '2026-07-31')`,
        );
      insert();
      insert();
      const appended = state.storage.sql
        .exec(
          "SELECT count(*) AS total FROM tracker_events WHERE event_id = 'ev-upgrade'",
        )
        .toArray() as { total: number }[];
      expect(appended[0].total, "the unique event_id index dedups appends").toBe(1);
      state.storage.sql.exec(
        "INSERT INTO tracker_aliases (content_id, alias) VALUES ('content-1', 'WS-1')",
      );
      const alias = state.storage.sql
        .exec("SELECT content_id FROM tracker_aliases WHERE alias = 'WS-1'")
        .toArray() as { content_id: string }[];
      expect(alias[0].content_id).toBe("content-1");
    });
  });

  it("refuses to serve an object stamped by a newer deploy (DR-0054 Phase B)", async () => {
    // A rolled-back worker attached to an object whose schema_migrations is
    // stamped past what it knows must fail closed — a structured 500 naming
    // both versions — instead of misreading (or lazily "upgrading") a layout
    // it has never seen. Nothing is deleted: the newer deploy serves it again.
    const sessionId = "session-schema-downgrade";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);

    // Read the stamp a FRESH object carries rather than hardcoding it. That is
    // what couples this test to `do_schema.sql`: adding a migration row without
    // bumping SUPPORTED_DO_SCHEMA_VERSION makes the deploy refuse the very state
    // it just wrote, and the assertion below catches it here instead of as two
    // dozen opaque 500s across the rest of the suite.
    let supported = 0;
    await runInDurableObject(stub, async (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT MAX(version) AS version FROM schema_migrations")
        .toArray() as { version: number }[];
      supported = rows[0].version;
    });
    expect(supported).toBeGreaterThan(0);

    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO schema_migrations (version, name) VALUES (99, 'from-the-future')",
      );
    });

    const response = await stub.fetch(
      "https://session.test/public/session/state",
      { headers: { authorization: "Bearer session-token" } },
    );
    expect(response.status).toBe(500);
    const body = await response.text();
    expect(body).toContain("version 99");
    expect(body).toContain(`version ${supported}`);
    expect(body).toContain("do not delete");

    // The refusal mutated nothing: the future stamp (and the object's state)
    // survive intact for the deploy that understands them.
    await runInDurableObject(stub, async (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT MAX(version) AS version FROM schema_migrations")
        .toArray() as { version: number }[];
      expect(rows[0].version).toBe(99);
    });
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

  // A failing turn already settles correctly. This pins that, because the live
  // observation gives it a new consequence: a client derives "busy" from
  // activity, so a turn that failed without a correlated terminal event would
  // no longer merely block the next turn — it would leave the composer disabled
  // with a "thinking" indicator that never clears.
  it("records the durable answer of a turn that ran a tool", async () => {
    // The suite could not drive a tool-USING turn at all before this: its one
    // hard-coded envelope grants no workspace capabilities, so every tool was
    // refused before dispatch. That blind spot is why the durable-assistant
    // regression reached production — the settle path behaves differently once
    // a turn has tool rounds, and nothing exercised that.
    //
    // This pins the end-to-end invariant (a settled tool turn records what it
    // answered). The narrower defect — an empty `assistant_text` winning over
    // streamed text — is pinned by the `selectAssistantText` unit tests, which
    // fail against the original `??`.
    // A handle is governed only when a binding resolves it to a declared
    // resource — the package's `file store project` needs both.
    const envelope = await mintSignedEnvelope(
      ["workspace.read", "workspace.write", "command.run"],
      {
        bindings: { project: "file_store:project", command: "command:bash" },
        resources: {
          // Unrestricted readers: the turn's context reaches the provider, and
          // the checker denies egress to a provider not cleared for everything
          // the turn read.
          "file_store:project": { reader: [], writer: [] },
          "command:bash": { reader: [], writer: [] },
        },
      },
    );
    let attempt = 0;
    const providerFetch = vi.fn(async () => {
      attempt += 1;
      if (attempt === 1) {
        return new Response(
          [
            `data: ${JSON.stringify({
              type: "response.output_item.done",
              item: {
                type: "function_call",
                call_id: "call-0",
                name: "write",
                arguments: JSON.stringify({ path: "note.txt", content: "hi" }),
              },
            })}`,
            "",
            'data: {"type":"response.completed","response":{"usage":{"input_tokens":4,"input_tokens_details":{"cached_tokens":0},"output_tokens":2}}}',
            "",
          ].join("\n"),
          { headers: { "content-type": "text/event-stream" } },
        );
      }
      return new Response(
        [
          'data: {"type":"response.output_text.delta","delta":"the streamed answer"}',
          "",
          'data: {"type":"response.completed","response":{"usage":{"input_tokens":5,"input_tokens_details":{"cached_tokens":0},"output_tokens":3}}}',
          "",
        ].join("\n"),
        { headers: { "content-type": "text/event-stream" } },
      );
    });
    vi.stubGlobal("fetch", providerFetch);

    const sessionId = "session-tool-answer-survives";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId, true, undefined, envelope);
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({ type: "session_ready", sequence: 0 });

    socket.send(JSON.stringify({
      type: "send_message",
      request_id: "turn-tool-answer",
      text: "write the note",
    }));
    let terminal: Record<string, unknown> | undefined;
    for (let index = 0; index < 160; index += 1) {
      const message = await nextMessage(socket);
      if (message.type === "turn_terminal" || message.type === "error") {
        terminal = message;
        break;
      }
    }
    expect(terminal).toMatchObject({ type: "turn_terminal", status: 200 });

    // The durable transcript is what survives a reload, and it is what `settle()`
    // restores over the streamed copy — so this, not the live view, is the test.
    const state = await stub.fetch("https://session.test/public/session/state", {
      headers: { authorization: "Bearer session-token" },
    });
    const projection = await state.json() as {
      transcript: { type: string; text: string }[];
    };
    // Exactly once. More than one settle site can reach the projection, and the
    // delta cursor only makes the streamed path idempotent — authoritative text
    // is not drawn from the cursor, so an unguarded push recorded the answer
    // twice and the reader saw the reply duplicated.
    expect(
      projection.transcript.filter((entry) => entry.type === "assistant"),
    ).toEqual([{ type: "assistant", text: "the streamed answer" }]);

    vi.unstubAllGlobals();
    socket.close(1000, "done");
  });

  it("records an answer for every turn in a session, not just the first", async () => {
    // A second turn is a different command, so nothing about settling the first
    // may suppress it. Apply-once markers keyed per command are exactly the kind
    // of guard that gets this wrong.
    const providerFetch = vi.fn(async () => new Response(
      [
        'data: {"type":"response.output_text.delta","delta":"an answer"}',
        "",
        'data: {"type":"response.completed","response":{"usage":{"input_tokens":3,"input_tokens_details":{"cached_tokens":0},"output_tokens":1}}}',
        "",
      ].join("\n"),
      { headers: { "content-type": "text/event-stream" } },
    ));
    vi.stubGlobal("fetch", providerFetch);

    const sessionId = "session-two-turns";
    const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
    const stub = namespace.get(namespace.idFromName(sessionId));
    await bootstrapSession(stub, sessionId);
    const socket = await openSocket(stub);
    expect(await nextMessage(socket)).toMatchObject({ type: "session_ready", sequence: 0 });

    for (const requestId of ["turn-one", "turn-two"]) {
      socket.send(JSON.stringify({ type: "send_message", request_id: requestId, text: `ask ${requestId}` }));
      for (let index = 0; index < 160; index += 1) {
        const message = await nextMessage(socket);
        if (message.type === "turn_terminal" || message.type === "error") {
          expect(message).toMatchObject({ type: "turn_terminal", request_id: requestId });
          break;
        }
      }
    }

    const state = await stub.fetch("https://session.test/public/session/state", {
      headers: { authorization: "Bearer session-token" },
    });
    const projection = await state.json() as { transcript: { type: string; text: string }[] };
    expect(projection.transcript.filter((entry) => entry.type === "assistant")).toEqual([
      { type: "assistant", text: "an answer" },
      { type: "assistant", text: "an answer" },
    ]);

    vi.unstubAllGlobals();
    socket.close(1000, "done");
  });

  it("settles a failed turn's client and leaves no active turn behind", async () => {
    // A provider that never succeeds, so the turn reaches its terminal state
    // through the failure path rather than a clean settle.
    const providerFetch = vi.fn(async () => {
      throw new Error("injected provider outage");
    });
    vi.stubGlobal("fetch", providerFetch);

    const sessionId = "session-turn-failure";
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
        request_id: "turn-fails",
        text: "hello",
      }),
    );
    const observed: Record<string, unknown>[] = [];
    for (let index = 0; index < 80; index += 1) {
      const message = await nextMessage(socket);
      observed.push(message);
      if (message.type === "turn_terminal" || message.type === "error") break;
    }

    // The failure has to arrive correlated. The bare socket `error` frame the
    // outer catch sends carries no request_id, so a client holding a pending
    // turn could never match it and would wait forever.
    expect(observed.at(-1)).toMatchObject({
      type: "error",
      request_id: "turn-fails",
      command_id: `public:${sessionId}:turn-fails`,
    });

    // The activity projection must have reported the turn before it failed —
    // otherwise nothing was observable during the very wait it exists for.
    expect(
      observed
        .filter(({ type }) => type === "turn_activity")
        .map(({ activity }) => activity),
    ).toContain("awaiting_model");

    // The singleton binding must be released. Leaving it behind pins the
    // session: every later turn 409s against a turn that already ended, and
    // each reconnecting client reads a permanently active turn from the
    // snapshot and sits disabled waiting on it.
    providerFetch.mockImplementation(async () =>
      new Response(
        [
          'data: {"type":"response.output_text.delta","delta":"recovered"}',
          "",
          'data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"input_tokens_details":{"cached_tokens":0},"output_tokens":1}}}',
          "",
        ].join("\n"),
        { headers: { "content-type": "text/event-stream" } },
      ),
    );
    socket.send(
      JSON.stringify({
        type: "send_message",
        request_id: "turn-after-failure",
        text: "again",
      }),
    );
    const recovered: Record<string, unknown>[] = [];
    for (let index = 0; index < 80; index += 1) {
      const message = await nextMessage(socket);
      recovered.push(message);
      if (message.type === "turn_terminal" || message.type === "error") break;
    }
    expect(recovered.at(-1)).toMatchObject({
      type: "turn_terminal",
      request_id: "turn-after-failure",
    });

    // And the released binding must leave no active turn for a reconnecting
    // client to inherit.
    const reconnected = await openSocket(stub);
    const ready = await nextMessage(reconnected);
    expect(
      (ready.snapshot as { active_turn?: unknown } | undefined)?.active_turn,
    ).toBeUndefined();
    socket.close(1000, "done");
    reconnected.close(1000, "done");
  });
});
