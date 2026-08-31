// The workspace-DO broker through the real Durable Object runtime: requests
// enter the WorkspaceBroker object over its binding and come out of the
// EXECUTOR namespace (TestExecutor stands in for the container pool, which
// cannot run under the vitest workers pool). Scheduling semantics — the
// priority guard, the queue bound, per-container slots — are proven in
// executor-broker.test.ts against the scheduler directly; this suite proves
// the wiring: routing, getRandom-compatible instance naming, request
// fidelity, and slot release across rounds.
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

type BrokerTestEnv = {
  WORKSPACE_BROKER: DurableObjectNamespace;
};

function brokerStub() {
  const namespace = (env as BrokerTestEnv).WORKSPACE_BROKER;
  return namespace.get(namespace.idFromName("workspace"));
}

function execRequest(extra: Record<string, unknown> = {}, priority?: string) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    authorization: "Bearer executor-token",
  };
  if (priority !== undefined) headers["x-whip-priority"] = priority;
  return {
    method: "POST",
    headers,
    body: JSON.stringify({ protocol: "whip-executor/1", ...extra }),
  };
}

// Generous per-test budget: these go through the real runtime, and the first
// request pays the module's cold start (the bundled wasm import alone can
// cross vitest's 5s default when the machine is busy).
const TEST_TIMEOUT_MS = 30_000;

describe("workspace broker", () => {
  it("routes an exec round to the pool with getRandom-compatible naming and forwards the request whole", { timeout: TEST_TIMEOUT_MS }, async () => {
    const response = await brokerStub().fetch(
      "http://executor/exec",
      execRequest({ marker: "round-trip" }, "working"),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      served_by: string;
      priority_header: string | null;
      body: { protocol: string; marker: string };
    };
    // An idle pool always places on the first instance (least-loaded order),
    // under the same instance-N names the routed pool warmed.
    expect(body.served_by).toBe("instance-0");
    expect(body.priority_header).toBe("working");
    expect(body.body.protocol).toBe("whip-executor/1");
    expect(body.body.marker).toBe("round-trip");
  });

  it("places overlapping rounds on distinct instances and frees slots afterwards", { timeout: TEST_TIMEOUT_MS }, async () => {
    const overlapping = await Promise.all([
      brokerStub().fetch("http://executor/exec", execRequest({ delay_ms: 300 })),
      brokerStub().fetch("http://executor/exec", execRequest({ delay_ms: 300 })),
    ]);
    const servedBy = await Promise.all(
      overlapping.map(async (response) => {
        expect(response.status).toBe(200);
        return ((await response.json()) as { served_by: string }).served_by;
      }),
    );
    expect(new Set(servedBy).size).toBe(2);
    for (const name of servedBy) {
      expect(name).toMatch(/^instance-[0-3]$/);
    }
    // Both slots came back: an idle-pool round is placed on the first
    // instance again rather than queued.
    const after = await brokerStub().fetch("http://executor/exec", execRequest());
    expect(((await after.json()) as { served_by: string }).served_by).toBe("instance-0");
  });
});
