// Helpers shared by the two workerd integration suites. The suites themselves
// are not redundant -- vitest.config.ts drives session.integration.test.ts
// against wrangler.test.toml and vitest.authenticated.config.ts drives
// authenticated-host.integration.test.ts against wrangler.authenticated.test.toml
// -- but these definitions were byte-identical in both, so they live here once.
import { runInDurableObject } from "cloudflare:test";
import { expect } from "vitest";

// The collection recipient the cross-language vector is addressed to. A test
// keypair with no production standing: the private half is here precisely so the
// captured vector can be opened, and the sealer never sees it — the DO is handed
// the public half alone, exactly as a tenant's release declares it.
export const COLLECTION_RECIPIENT_PRIVATE_SEED_HEX =
  "624b847dff874876d18980a7d12c116f4848421302e09569efb3fa62cca47b85";
export const COLLECTION_RECIPIENT_PUBLIC_KEY_HEX =
  "04e98c4b5e749038c87fb11e238ea748e0e7b3c952d91e909dbf22084afe86fc4d28dbedee9b3449323fdf6ebaa02810666ed917e4a6dc0b70725bcbff0438d1a0";

export type TestEnv = {
  WORKFLOW_INSTANCE: DurableObjectNamespace;
  SESSION_ADMISSION: DurableObjectNamespace;
};

function hex(bytes: Uint8Array): string {
  return [...bytes]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256(value: string): Promise<string> {
  return hex(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  );
}

export async function packageDocuments(withTools = false) {
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

export function nextMessage(socket: WebSocket): Promise<Record<string, unknown>> {
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

export async function openSocket(
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

export async function durableStringValues(stub: DurableObjectStub): Promise<string[]> {
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
