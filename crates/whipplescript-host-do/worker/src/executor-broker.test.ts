import assert from "node:assert/strict";
import test from "node:test";
import {
  BrokerRefusal,
  BrokerScheduler,
  DEFAULT_POOL_SIZE,
  PRIORITY_HEADER,
  executorInstanceName,
  executorPoolSize,
  handleBrokeredExec,
  priorityClass,
} from "./executor-broker.ts";

// Let already-resolved promises run their continuations.
const settle = () => new Promise((resolve) => setImmediate(resolve));

test("priority classes mirror the executor's mapping: unlabeled is live traffic", () => {
  assert.equal(priorityClass("production"), 0);
  assert.equal(priorityClass("working"), 1);
  assert.equal(priorityClass("counterfactual"), 2);
  assert.equal(priorityClass(null), 0);
  assert.equal(priorityClass(undefined), 0);
  assert.equal(priorityClass("anything-else"), 0);
});

test("a free pool grants immediately", async () => {
  const scheduler = new BrokerScheduler(2, 1, 8);
  const lease = await scheduler.acquire(2);
  assert.ok(lease.container === 0 || lease.container === 1);
});

// The [serve] guard from compute-priority-queue.maude, transcribed here for
// the workspace tier exactly as exec_server.rs transcribes it per-executor:
// a freed slot never serves a request while a strictly higher-priority
// request waits.
test("a freed slot serves production before counterfactual regardless of arrival order", async () => {
  const scheduler = new BrokerScheduler(1, 1, 8);
  const held = await scheduler.acquire(0);
  const order: string[] = [];
  const counterfactual = scheduler.acquire(2).then((lease) => {
    order.push("counterfactual");
    return lease;
  });
  const production = scheduler.acquire(0).then((lease) => {
    order.push("production");
    return lease;
  });
  held.release();
  (await production).release();
  (await counterfactual).release();
  assert.deepEqual(order, ["production", "counterfactual"]);
});

test("waiters within one class are served in arrival order", async () => {
  const scheduler = new BrokerScheduler(1, 1, 8);
  const held = await scheduler.acquire(0);
  const order: number[] = [];
  const waiters = [1, 2, 3].map((id) =>
    scheduler.acquire(1).then((lease) => {
      order.push(id);
      return lease;
    }),
  );
  held.release();
  for (const waiter of waiters) {
    (await waiter).release();
  }
  assert.deepEqual(order, [1, 2, 3]);
});

test("placement spreads load and never exceeds the per-container bound", async () => {
  const scheduler = new BrokerScheduler(2, 2, 8);
  const inFlight = new Map<number, number>();
  const leases = [];
  for (let i = 0; i < 4; i += 1) {
    const lease = await scheduler.acquire(0);
    inFlight.set(lease.container, (inFlight.get(lease.container) ?? 0) + 1);
    leases.push(lease);
  }
  // Least-loaded placement fills evenly: two rounds through both containers.
  assert.deepEqual([...inFlight.values()].sort(), [2, 2]);
  // A fifth acquire waits — both containers are at their slot bound.
  let granted = false;
  const fifth = scheduler.acquire(0).then((lease) => {
    granted = true;
    return lease;
  });
  await settle();
  assert.equal(granted, false);
  leases[0].release();
  (await fifth).release();
  for (const lease of leases.slice(1)) lease.release();
});

test("release is idempotent: a double release mints no phantom slot", async () => {
  const scheduler = new BrokerScheduler(1, 1, 8);
  const first = await scheduler.acquire(0);
  first.release();
  first.release();
  const second = await scheduler.acquire(0);
  let granted = false;
  const third = scheduler.acquire(0).then((lease) => {
    granted = true;
    return lease;
  });
  await settle();
  assert.equal(granted, false);
  second.release();
  (await third).release();
});

test("a full wait queue is refused loudly, and drains back below the bound", async () => {
  const scheduler = new BrokerScheduler(1, 1, 1);
  const held = await scheduler.acquire(0);
  const queued = scheduler.acquire(0);
  await assert.rejects(scheduler.acquire(0), BrokerRefusal);
  held.release();
  const lease = await queued;
  // The queue drained, so the next request queues instead of being refused.
  const next = scheduler.acquire(0);
  lease.release();
  (await next).release();
});

test("a pool scaled to zero is refused, not queued forever", async () => {
  const scheduler = new BrokerScheduler(0, 4, 8);
  await assert.rejects(scheduler.acquire(0), BrokerRefusal);
});

test("the pool-size knob defaults, parses, and refuses garbage", () => {
  assert.equal(executorPoolSize(undefined), DEFAULT_POOL_SIZE);
  assert.equal(executorPoolSize(""), DEFAULT_POOL_SIZE);
  assert.equal(executorPoolSize("0"), 0);
  assert.equal(executorPoolSize("9"), 9);
  assert.throws(() => executorPoolSize("many"));
  assert.throws(() => executorPoolSize("-1"));
  assert.throws(() => executorPoolSize("2.5"));
});

test("container naming matches the routed pool's getRandom naming", () => {
  assert.equal(executorInstanceName(0), "instance-0");
  assert.equal(executorInstanceName(3), "instance-3");
});

test("handleBrokeredExec forwards the request whole and releases after the round", async () => {
  const scheduler = new BrokerScheduler(1, 1, 8);
  const served: { container: number; body: string; priority: string | null }[] = [];
  const forward = async (container: number, request: Request) => {
    served.push({
      container,
      body: await request.text(),
      priority: request.headers.get(PRIORITY_HEADER),
    });
    return Response.json({ ok: true });
  };
  const request = (priority: string) =>
    new Request("http://executor/exec", {
      method: "POST",
      headers: { [PRIORITY_HEADER]: priority, authorization: "Bearer token" },
      body: JSON.stringify({ protocol: "whip-executor/1", priority }),
    });
  const first = await handleBrokeredExec(request("production"), scheduler, forward);
  assert.equal(first.status, 200);
  // The slot came back after the round: a second exec is served, not queued.
  const second = await handleBrokeredExec(request("counterfactual"), scheduler, forward);
  assert.equal(second.status, 200);
  assert.equal(served.length, 2);
  assert.equal(served[0].priority, "production");
  assert.equal(JSON.parse(served[0].body).protocol, "whip-executor/1");
  assert.equal(served[1].priority, "counterfactual");
});

test("handleBrokeredExec releases the slot when the container round throws", async () => {
  const scheduler = new BrokerScheduler(1, 1, 8);
  const failing = new Request("http://executor/exec", { method: "POST", body: "{}" });
  await assert.rejects(
    handleBrokeredExec(failing, scheduler, async () => {
      throw new Error("container unreachable");
    }),
    /container unreachable/,
  );
  const lease = await scheduler.acquire(0);
  lease.release();
});

test("handleBrokeredExec maps a refusal to an error body the core settles cleanly", async () => {
  const scheduler = new BrokerScheduler(0, 4, 8);
  const response = await handleBrokeredExec(
    new Request("http://executor/exec", { method: "POST", body: "{}" }),
    scheduler,
    async () => Response.json({ ok: true }),
  );
  assert.equal(response.status, 503);
  const body = (await response.json()) as { error?: string };
  assert.match(body.error ?? "", /scaled to zero/);
});
