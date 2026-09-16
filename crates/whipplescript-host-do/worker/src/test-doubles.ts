import { ExecutorController } from "./executor-controller";
import { ExecutorControllerRoutes } from "./executor-controller-routes";
import * as bindings from "../pkg/whipplescript_host_do_bg.js";
// The Durable Object test doubles both test workers stand up: the embedder's
// session-admission stand-in and the public-credential resolver stand-in.
// wrangler.test.toml and wrangler.authenticated.test.toml both bind these two
// class names, so each entry module re-exports them from here.

export class TestDeployment implements DurableObject {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    if (
      request.headers.get("authorization") !==
        "Bearer public-control-secret"
    ) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const match = new URL(request.url).pathname.match(
      /^\/internal\/sessions\/([^/]+)\/(admit|settle|release|expire|deposit)$/,
    );
    if (!match || request.method !== "POST") {
      return Response.json({ error: "not found" }, { status: 404 });
    }
    const body = await request.json<Record<string, unknown>>();
    const sessionId = decodeURIComponent(match[1]);
    const operationKey = `operation:${sessionId}:${match[2]}`;
    const operationCount =
      (await this.state.storage.get<number>(operationKey)) ?? 0;
    await this.state.storage.put(operationKey, operationCount + 1);
    if (match[2] === "deposit") {
      // Stand-in for the embedder's custody: hold what was handed over so the
      // test can assert what actually left the session.
      await this.state.storage.put(`collection:${sessionId}`, body);
      return Response.json({ deposited: true }, { status: 201 });
    }
    if (match[2] === "admit") {
      const requestId = String(body.request_id ?? "");
      const key = `reservation:${sessionId}:${requestId}`;
      const existing = await this.state.storage.get<string>(key);
      const reservationRef =
        existing ?? `reservation:${sessionId}:${requestId}`;
      if (!existing) await this.state.storage.put(key, reservationRef);
      return Response.json(
        { reservation_ref: reservationRef, maximum_tokens: 32_768 },
        { status: existing ? 200 : 201 },
      );
    }
    return Response.json({
      reservation_ref: body.reservation_ref,
      operation: match[2],
    });
  }
}

// Uses the real controller routes, SQLite and WASM reducers. Its process port
// echoes pool identity and the dispatch body so broker tests run in workerd
// without a physical container.
export class TestExecutor implements DurableObject {
  private readonly routes: ExecutorControllerRoutes;
  constructor(private readonly state: DurableObjectState) {
    const owner = state.id.name;
    if (!owner) throw new Error("test executor requires owner identity");
    this.routes = new ExecutorControllerRoutes(new ExecutorController(state.storage, owner, bindings.exec_controller_transition, {
      inspect: bindings.exec_barrier_inspect, begin: bindings.exec_barrier_begin, finish: bindings.exec_barrier_finish,
    }), {
      runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read,
      delivery: bindings.exec_incarnation_delivery,
      result: bindings.exec_incarnation_result,
    }, async () => {
      state.storage.sql.exec("CREATE TABLE IF NOT EXISTS executor_test_process (incarnation TEXT)");
      if (state.storage.sql.exec("SELECT incarnation FROM executor_test_process").toArray().length === 0) {
        state.storage.sql.exec("INSERT INTO executor_test_process VALUES (?)", crypto.randomUUID());
      }
      state.storage.sql.exec("CREATE TABLE IF NOT EXISTS executor_test_starts (started INTEGER)");
      state.storage.sql.exec("INSERT INTO executor_test_starts VALUES (1)");
    }, request => this.raw(request), async () => {
      state.storage.sql.exec("DELETE FROM executor_test_process");
    });
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path.startsWith("/exec/controller/")) return this.routes.fetch(request);
    if (request.method !== "POST" || path !== "/exec") {
      return Response.json({ error: "not found" }, { status: 404 });
    }
    return this.execute(request, await request.json());
  }

  private async raw(request: Request): Promise<Response> {
    const incarnation = this.state.storage.sql.exec<{ incarnation: string }>("SELECT incarnation FROM executor_test_process").one().incarnation;
    if (new URL(request.url).pathname === "/exec/incarnation") {
      return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation });
    }
    const delivery = await request.json<{ protocol: string; incarnation: string; dispatch: unknown }>();
    if (delivery.protocol !== "whipplescript.exec.incarnation/v1" || delivery.incarnation !== incarnation) {
      return Response.json({ error: "stale incarnation" }, { status: 409 });
    }
    const response = await this.execute(request, delivery.dispatch);
    return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation, status: response.status, body: await response.json() });
  }

  private async execute(request: Request, value: unknown): Promise<Response> {
    const body = value as { delay_ms?: number; effect_id?: string };
    this.state.storage.sql.exec("CREATE TABLE IF NOT EXISTS executor_test_calls (effect_id TEXT)");
    this.state.storage.sql.exec("INSERT INTO executor_test_calls (effect_id) VALUES (?)", body.effect_id ?? "");
    if (typeof body.delay_ms === "number" && body.delay_ms > 0) {
      await new Promise((resolve) => setTimeout(resolve, body.delay_ms));
    }
    return Response.json({
      execution_id: crypto.randomUUID(),
      served_by: this.state.id.name ?? "<anonymous>",
      priority_header: request.headers.get("x-whip-priority"),
      dispatch_header: request.headers.get("x-whip-exec-dispatch"),
      body,
    });
  }
}

export class TestCredentialRegistry implements DurableObject {
  async fetch(request: Request): Promise<Response> {
    if (
      request.headers.get("authorization") !==
        "Bearer public-control-secret"
    ) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const body = await request.json<{ credential_ref?: string }>();
    if (
      request.method !== "POST" ||
      new URL(request.url).pathname !== "/resolve" ||
      body.credential_ref !==
        `credential:public:${"a".repeat(64)}:openai:${"b".repeat(32)}`
    ) {
      return Response.json({ error: "not found" }, { status: 404 });
    }
    return Response.json({
      credential_ref: body.credential_ref,
      provider: "openai",
      credential_class: "managed-openai",
      api_key: "canary-provider-secret-must-not-persist",
    });
  }
}
