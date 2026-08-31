// The workspace-DO broker for the Class-A executor pool (compute plane P8,
// spec/compute-plane-design-note.md §3/§6): "a workspace-level warm pool,
// owned by the workspace DO". Every whip-executor/1 exec round flows through
// one WorkspaceBroker object per deployment, which admits it under the
// verified priority discipline (models/maude/compute-priority-queue.maude —
// production > working > counterfactual) and places it on the least-loaded
// container. Before the broker, the [serve] guard lived only inside each
// executor process, so location-blind random routing could hand every
// container to counterfactual work while production queued behind whichever
// instance it happened to land on; the broker holds the guard workspace-wide,
// which is the scheduling residual §6 assigns to this tier.
//
// The scheduler state is in-memory, like the executor's own process-local
// AdmissionGate: the broker never hibernates while requests are in flight,
// and an eviction fails those fetches back to their workflow DOs as
// TransportError terminals — the documented at-least-once posture
// (DR-0033 Decision 3). There is nothing durable to lose.
//
// This module is imported by node --test files under --experimental-strip-types,
// so it must stay free of non-erasable TypeScript (no parameter properties,
// no enums).

/** Priority classes, best first: production(0) > working(1) > counterfactual(2). */
export const PRIORITY_CLASSES = 3;

/**
 * Mirrors `priority_class` in crates/whipplescript-cli/src/exec_server.rs:
 * unlabeled requests are live traffic.
 */
export function priorityClass(name: string | null | undefined): number {
  switch (name) {
    case "working":
      return 1;
    case "counterfactual":
      return 2;
    default:
      return 0;
  }
}

/**
 * Per-container exec slots. Keep in step with `EXEC_SLOTS` in
 * crates/whipplescript-cli/src/exec_server.rs — the broker admits exactly as
 * much per container as the executor process will run without queueing, so
 * with all traffic brokered the workspace queue is the only queue.
 */
export const SLOTS_PER_CONTAINER = 4;

/**
 * Fixed pool size until platform autoscaling ships (design note §3: a manual
 * knob with a working zero-config default). Overridden per deployment by
 * `WHIP_EXECUTOR_POOL_SIZE`, which must be kept in step with the wrangler
 * config's `[[containers]] max_instances`.
 */
export const DEFAULT_POOL_SIZE = 4;

/**
 * Bound on waiters held in the broker's queue. A waiter is a pending request
 * whose body (inline sha-pinned script bytes) is held in the object's memory,
 * so an unbounded queue under runaway regeneration would grow without limit;
 * past the bound the broker refuses loudly instead of degrading silently.
 */
export const MAX_WAITING = 256;

/** Admission header derived from the whip-executor/1 body's `priority` field. */
export const PRIORITY_HEADER = "x-whip-priority";

/**
 * An admission the broker refuses outright (over-capacity queue, or a pool
 * scaled to zero). `handleBrokeredExec` maps it to a `{"error": ...}` body,
 * which the core turns into a TransportError terminal — the effect settles
 * cleanly instead of hanging.
 */
export class BrokerRefusal extends Error {}

export interface BrokerLease {
  /** Pool index of the granted container. */
  container: number;
  /** Return the slot; idempotent. */
  release(): void;
}

type Grant = (lease: BrokerLease) => void;

/**
 * The workspace-wide admission gate + placement. Transcribes the verified
 * [serve] guard from models/maude/compute-priority-queue.maude: a slot is
 * granted to a waiter only when no strictly higher-priority waiter exists.
 * Placement picks the container with the most free slots, so per-container
 * concurrency never exceeds SLOTS_PER_CONTAINER by construction.
 *
 * All state transitions are synchronous (no awaits inside), so the object's
 * single-threaded event loop makes them atomic under concurrent requests.
 */
export class BrokerScheduler {
  private readonly freeSlots: number[];
  private readonly waiting: Grant[][];
  private readonly maxWaiting: number;
  private waitingCount = 0;

  constructor(containers: number, slotsPerContainer: number, maxWaiting: number) {
    this.freeSlots = Array.from({ length: containers }, () => slotsPerContainer);
    this.waiting = Array.from({ length: PRIORITY_CLASSES }, () => []);
    this.maxWaiting = maxWaiting;
  }

  /**
   * Acquire a slot at `priority` (0 best). Resolves when granted; rejects
   * with BrokerRefusal when the pool is scaled to zero or the queue is full.
   * A queued waiter is never rejected later — it waits until served, the
   * same posture as the executor's own gate.
   */
  acquire(priority: number): Promise<BrokerLease> {
    if (this.freeSlots.length === 0) {
      return Promise.reject(
        new BrokerRefusal(
          "the executor pool is scaled to zero (WHIP_EXECUTOR_POOL_SIZE); raise it together with the container max_instances",
        ),
      );
    }
    // A free slot cannot coexist with a non-empty queue: release() grants
    // waiters synchronously while slots are free. So granting immediately
    // here never overtakes a waiter, and the model's guard holds trivially.
    const container = this.leastLoadedFree();
    if (container !== undefined) {
      return Promise.resolve(this.grant(container));
    }
    if (this.waitingCount >= this.maxWaiting) {
      return Promise.reject(
        new BrokerRefusal(
          `the workspace executor queue is full (${this.maxWaiting} waiting); retry after in-flight work drains`,
        ),
      );
    }
    this.waitingCount += 1;
    return new Promise((resolve) => {
      this.waiting[priority].push(resolve);
    });
  }

  /** The container with the most free slots, or undefined when none is free. */
  private leastLoadedFree(): number | undefined {
    let best: number | undefined;
    for (let index = 0; index < this.freeSlots.length; index += 1) {
      if (this.freeSlots[index] > 0 && (best === undefined || this.freeSlots[index] > this.freeSlots[best])) {
        best = index;
      }
    }
    return best;
  }

  private grant(container: number): BrokerLease {
    this.freeSlots[container] -= 1;
    let released = false;
    return {
      container,
      release: () => {
        if (released) return;
        released = true;
        this.freeSlots[container] += 1;
        this.serveWaiters();
      },
    };
  }

  // The [serve] guard, live: every freed slot goes to the head of the
  // highest-priority non-empty class (FIFO within a class), so a request is
  // never served while a strictly higher-priority request waits.
  private serveWaiters(): void {
    for (;;) {
      const container = this.leastLoadedFree();
      if (container === undefined) return;
      const queue = this.waiting.find((waiters) => waiters.length > 0);
      if (queue === undefined) return;
      const resolve = queue.shift();
      if (resolve === undefined) return;
      this.waitingCount -= 1;
      resolve(this.grant(container));
    }
  }
}

/**
 * The pool container a broker index addresses. Matches the naming
 * `@cloudflare/containers` getRandom uses, so the brokered pool reuses the
 * same warm instances the routed pool did.
 */
export function executorInstanceName(container: number): string {
  return `instance-${container}`;
}

/**
 * Parse the manual pool-size knob. Unset means the zero-config default;
 * anything else must be a whole number — a misread knob fails loudly rather
 * than silently running some other pool size.
 */
export function executorPoolSize(value: string | undefined): number {
  if (value === undefined || value === "") {
    return DEFAULT_POOL_SIZE;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`WHIP_EXECUTOR_POOL_SIZE must be a whole number, got ${JSON.stringify(value)}`);
  }
  return parsed;
}

/**
 * One brokered exec round: admit under the priority discipline, forward to
 * the granted container, release the slot when the round settles. The slot is
 * held for the whole container round — that is what makes the workspace bound
 * real rather than advisory.
 */
export async function handleBrokeredExec(
  request: Request,
  scheduler: BrokerScheduler,
  forward: (container: number, request: Request) => Promise<Response>,
): Promise<Response> {
  const priority = priorityClass(request.headers.get(PRIORITY_HEADER));
  let lease: BrokerLease;
  try {
    lease = await scheduler.acquire(priority);
  } catch (error) {
    if (error instanceof BrokerRefusal) {
      return Response.json({ error: error.message }, { status: 503 });
    }
    throw error;
  }
  try {
    return await forward(lease.container, request);
  } finally {
    lease.release();
  }
}

// The slice of the worker Env the broker reads. Declared locally (rather than
// importing index.ts's Env) so this module has no import cycle and stays
// loadable under plain node for its unit tests.
interface BrokerEnv {
  EXECUTOR: {
    idFromName(name: string): unknown;
    get(id: unknown): { fetch(input: Request): Promise<Response> };
  };
  WHIP_EXECUTOR_POOL_SIZE?: string;
}

/**
 * The workspace DO owning Class-A placement. One instance per deployment
 * (idFromName("workspace") — the deploy unit is the workspace, design note
 * §8); it is reachable only over its binding from this worker's workflow DOs,
 * never from a public route.
 */
export class WorkspaceBroker {
  private readonly env: BrokerEnv;
  private readonly scheduler: BrokerScheduler;

  constructor(_state: unknown, env: BrokerEnv) {
    this.env = env;
    this.scheduler = new BrokerScheduler(
      executorPoolSize(env.WHIP_EXECUTOR_POOL_SIZE),
      SLOTS_PER_CONTAINER,
      MAX_WAITING,
    );
  }

  async fetch(request: Request): Promise<Response> {
    return handleBrokeredExec(request, this.scheduler, (container, forwarded) => {
      const pool = this.env.EXECUTOR;
      const stub = pool.get(pool.idFromName(executorInstanceName(container)));
      return stub.fetch(forwarded);
    });
  }
}
