import { ExecutorController, type ControllerAction } from "./executor-controller";

export interface IncarnationCodec {
  runtime(placement: string, profile?: string): void;
  read(response: string): string;
  delivery(incarnation: string, dispatch: string): string;
  result(response: string, expected: string): string;
}

// Shared by the actual container class and the workerd test process port.
// Only a fresh delivery may prepare a process. Read and fence never call start.
type ActiveWork = { abort: AbortController; done: Promise<unknown> };

export class ExecutorControllerRoutes {
  private readonly preparing = new Set<ActiveWork>();
  private readonly executing = new Set<ActiveWork>();
  private barrierWork: Promise<void> | undefined;
  constructor(
    private readonly controller: ExecutorController,
    private readonly codec: IncarnationCodec,
    private readonly start: (signal: AbortSignal) => Promise<void>,
    private readonly raw: (request: Request) => Promise<Response>,
    private readonly destroy: () => Promise<void> = async () => { throw new Error("physical executor destruction binding is required"); },
    private readonly normRuntime?: { profile: string; verify: (receipt: string, incarnation: string, profile: string) => void },
  ) {}

  private track<T>(set: Set<ActiveWork>, parent: AbortSignal, work: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const abort = new AbortController();
    const signal = AbortSignal.any([parent, abort.signal]);
    const done = (async () => { signal.throwIfAborted(); return work(signal); })();
    const entry = { abort, done };
    set.add(entry);
    void done.then(() => set.delete(entry), () => set.delete(entry));
    return done;
  }

  private async drain(set: Set<ActiveWork>): Promise<void> {
    const pending = [...set];
    for (const entry of pending) entry.abort.abort(new Error("executor termination barrier"));
    await Promise.allSettled(pending.map(entry => entry.done));
  }

  private completeBarrier(): Promise<void> {
    if (this.barrierWork) return this.barrierWork;
    const gate = this.controller.beginBarrier();
    if (!gate.closing) return Promise.resolve();
    const work = (async () => {
      // The durable gate prevents new preparation/admission. Settle all prior
      // startup continuations before destruction, including legacy fetches.
      await this.drain(this.preparing);
      await this.destroy();
      // A response already in flight may still retain its completion. Drain
      // those callbacks before the terminal records and barrier generation commit.
      await this.drain(this.executing);
      this.controller.finishBarrier(gate.barrier_id);
    })();
    this.barrierWork = work;
    void work.then(() => { this.barrierWork = undefined; }, () => { this.barrierWork = undefined; });
    return work;
  }

  async legacy(request: Request, forward: (request: Request) => Promise<Response>): Promise<Response> {
    if (this.controller.gate().closing) return Response.json({ error: "executor termination barrier is active" }, { status: 503 });
    return this.track(this.preparing, request.signal, signal => forward(new Request(request, { signal })));
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST" || !["/exec/controller/deliver", "/exec/controller/read", "/exec/controller/fence"].includes(path)) {
      return Response.json({ error: "unknown controller route" }, { status: 404 });
    }
    const command = await request.json() as { placement: unknown; fence_id?: string };
    const placement = JSON.stringify(command.placement);
    let action: ControllerAction = this.controller.read(placement);
    if (path === "/exec/controller/fence") {
      // Join an existing controller intent using its original identity. Validate
      // even a resumed request before allowing physical barrier work.
      action = this.controller.ensureFence(placement, command.fence_id ?? "");
      if (action.action === "fence_required" || this.controller.gate().closing) {
        await this.completeBarrier();
        action = this.controller.read(placement);
      }
    } else if (path === "/exec/controller/deliver" && action.action === "absent") {
      this.codec.runtime(placement, this.normRuntime?.profile);
      // Resume a persisted barrier after eviction before preparing a new process.
      if (this.controller.gate().closing) await this.completeBarrier();
      const observedGeneration = this.controller.gate().generation;
      // Preparation grants no command admission. Its generation must still
      // match when the admission transaction runs after the handshake.
      await this.track(this.preparing, request.signal, signal => this.start(signal));
      action = this.controller.read(placement);
      if (action.action === "absent") {
        const headers = new Headers(request.headers);
        headers.delete("content-length");
        const health = await this.raw(new Request("http://container/exec/incarnation", { headers }));
        if (health.status !== 200) throw new Error("executor incarnation query failed");
        const incarnation = this.codec.read(await health.text());
        if (this.normRuntime) {
          await this.track(this.preparing, request.signal, async signal => {
            const proof = await this.raw(new Request("http://container/exec/norm-runtime", { headers, signal }));
            if (proof.status !== 200) { await proof.body?.cancel(); throw new Error("executor norm runtime query failed"); }
            this.normRuntime!.verify(await proof.text(), incarnation, this.normRuntime!.profile);
          });
        }
        action = await this.track(this.executing, request.signal, signal => this.controller.execute(placement, incarnation, async dispatch => {
          // Raw port only: this call must never auto-start a replacement process.
          const response = await this.raw(new Request("http://container/exec/bound", {
            method: "POST", headers, signal, body: this.codec.delivery(incarnation, JSON.stringify(dispatch)),
          }));
          if (response.status !== 200) throw new Error("bound executor delivery failed");
          return JSON.parse(this.codec.result(await response.text(), incarnation)) as { status: number; body: unknown };
        }, observedGeneration));
      }
    }
    return Response.json({ protocol: "whipplescript.exec.controller.response/v1", placement: command.placement, action });
  }
}
