import { ExecutorController } from "./executor-controller";
import * as bindings from "../pkg/whipplescript_host_do_bg.js";
// The workspace-DO broker through the real Durable Object runtime: requests
// enter the WorkspaceBroker object over its binding and come out of the
// EXECUTOR namespace (TestExecutor stands in for the container pool, which
// cannot run under the vitest workers pool). Scheduling semantics — the
// priority guard, the queue bound, per-container slots — are proven in
// executor-broker.test.ts against the scheduler directly; this suite proves
// the wiring: routing, getRandom-compatible instance naming, request
// fidelity, and slot release across rounds.
import { env } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

type BrokerTestEnv = {
  WORKSPACE_BROKER: DurableObjectNamespace;
  EXECUTOR: DurableObjectNamespace;
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

// Use the shared workerd bound from vitest.config.ts / test-bounds.ts. The
// first request pays the module's cold start, including the bundled wasm.

describe("workspace broker", () => {
  it("routes an exec round to the pool with getRandom-compatible naming and forwards the request whole", async () => {
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

  it("places overlapping rounds on distinct instances and frees slots afterwards", async () => {
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

async function invocationRequest(effect: string, admission: string | null = null) {
  const selected = { instance_id: "broker-fixture", effect_id: effect, attempt_admission_event_id: admission };
  const parts = [selected.instance_id, effect, "exec-run", ...(admission === null ? [] : ["admission", admission])];
  const material = parts.map(part => `${new TextEncoder().encode(part).length}:${part};`).join("");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material)));
  const run_id = "key_" + [...digest.slice(0, 16)].map(byte => byte.toString(16).padStart(2, "0")).join("");
  return { selected, envelope: {
    protocol: "whipplescript.exec.invocation/v1", invocation: selected, run_id,
    dispatch: { protocol: "whip-executor/1", effect_id: effect, delay_ms: 100, stdin: { original: true } },
  } };
}

function invoke(command: unknown) {
  return brokerStub().fetch("http://executor/exec/invocation", {
    method: "POST", headers: { "content-type": "application/json", authorization: "Bearer executor-token" },
    body: JSON.stringify(command),
  });
}

async function executorCalls(effect: string) {
  const namespace = (env as BrokerTestEnv).EXECUTOR;
  const counts = await Promise.all([0, 1, 2, 3].map(index => runInDurableObject(namespace.get(namespace.idFromName(`instance-${index}`)), async (_instance, state) => {
    state.storage.sql.exec("CREATE TABLE IF NOT EXISTS executor_test_calls (effect_id TEXT)");
    return state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM executor_test_calls WHERE effect_id = ?", effect).one().count;
  })));
  return counts.reduce((sum, count) => sum + count, 0);
}

describe("durable executor receipts", () => {
  it("keeps legacy placements unresolved without querying or upgrading them", async () => {
    const command = await invocationRequest("legacy-placement");
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      const selected = JSON.stringify(command.selected);
      const envelope = JSON.stringify(command.envelope);
      const claim = JSON.parse(bindings.exec_provider_claim(selected, envelope));
      const receipt = JSON.stringify(claim.decision.receipt);
      const placement = bindings.exec_provider_place(selected, envelope, receipt, undefined, "instance-0", "legacy-dispatch");
      state.storage.sql.exec("INSERT INTO exec_provider_receipts_v1 VALUES (?, ?)", claim.storage_key, receipt);
      state.storage.sql.exec("INSERT INTO exec_provider_placements_v1 VALUES (?, ?)", claim.storage_key, placement);
    });
    await evictDurableObject(brokerStub());
    const response = await invoke(command);
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ protocol: "whipplescript.exec.reconciliation/v1", state: "pending" });
    expect(await executorCalls("legacy-placement")).toBe(0);
  });

  it("does not forward before the claim commits", async () => {
    const command = await invocationRequest("failed-claim");
    await (await brokerStub().fetch("http://executor/exec", execRequest())).arrayBuffer();
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      state.storage.sql.exec("CREATE TRIGGER fail_receipt_claim AFTER INSERT ON exec_provider_receipts_v1 BEGIN SELECT RAISE(ABORT, 'injected claim failure'); END");
    });
    await expect(invoke(command)).rejects.toThrow();
    expect(await executorCalls("failed-claim")).toBe(0);
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      state.storage.sql.exec("DROP TRIGGER fail_receipt_claim");
      expect(state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM exec_provider_receipts_v1 WHERE json_extract(invocation, '$[1].effect_id') = 'failed-claim'").one().count).toBe(0);
    });
    const completed = await invoke(command);
    expect(completed.status).toBe(200);
    await completed.arrayBuffer();
    expect(await executorCalls("failed-claim")).toBe(1);
  });
  it.each(["ABORT", "IGNORE"] as const)("does not forward when durable placement is not retained (%s)", async (fault) => {
    const effect = `failed-placement-${fault}`;
    const command = await invocationRequest(effect);
    await (await brokerStub().fetch("http://executor/exec", execRequest())).arrayBuffer();
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      state.storage.sql.exec(`CREATE TRIGGER fail_placement BEFORE INSERT ON exec_provider_placements_v1 BEGIN SELECT RAISE(${fault === "ABORT" ? "ABORT, 'injected placement failure'" : "IGNORE"}); END`);
    });
    try {
      await expect(invoke(command).then(async response => {
        // Drain unexpected success too, so a caught control does not strand
        // a response stream and poison later eviction fixtures.
        await response.arrayBuffer();
        return response;
      })).rejects.toThrow();
    } finally {
      await runInDurableObject(brokerStub(), async (_instance, state) => {
        state.storage.sql.exec("DROP TRIGGER fail_placement");
      });
    }
    expect(await executorCalls(effect)).toBe(0);
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      expect(state.storage.sql.exec("SELECT placement_json FROM exec_provider_placements_v1 WHERE json_extract(invocation, '$[1].effect_id') = ?", effect).toArray()).toEqual([]);
      const row = state.storage.sql.exec<{ receipt_json: string }>("SELECT receipt_json FROM exec_provider_receipts_v1 WHERE json_extract(invocation, '$[1].effect_id') = ?", effect).one();
      expect(JSON.parse(row.receipt_json).state).toBe("started");
    });
    await evictDurableObject(brokerStub());
    const replay = await invoke(command);
    expect(replay.status).toBe(202);
    await replay.arrayBuffer();
    expect(await executorCalls(effect)).toBe(0);
  });

  it("claims once across concurrent requests and replays after eviction", async () => {
    const command = await invocationRequest("concurrent");
    const responses = await Promise.all([invoke(command), invoke(command)]);
    expect(responses.some(response => response.status === 200)).toBe(true);
    const original = await responses.find(response => response.status === 200)!.clone().json();
    // Both requests are issued together, but the second may reach the broker
    // after completion. Either pending or the identical retained result is valid.
    for (const response of responses) {
      expect([200, 202]).toContain(response.status);
      expect(await response.json()).toEqual(response.status === 200 ? original : { protocol: "whipplescript.exec.reconciliation/v1", state: "pending" });
    }
    await evictDurableObject(brokerStub());
    expect(await (await invoke(command)).json()).toEqual(original);
    expect(await executorCalls("concurrent")).toBe(1);
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      const rows = state.storage.sql.exec<{ receipt_json: string }>("SELECT receipt_json FROM exec_provider_receipts_v1 WHERE json_extract(invocation, '$[1].effect_id') = 'concurrent'").toArray();
      expect(rows).toHaveLength(1);
      expect(rows[0].receipt_json).not.toContain("executor-token");
      const placed = state.storage.sql.exec<{ placement_json: string }>("SELECT placement_json FROM exec_provider_placements_v1 WHERE json_extract(invocation, '$[1].effect_id') = 'concurrent'").toArray();
      expect(placed).toHaveLength(1);
      const placement = JSON.parse(placed[0].placement_json);
      expect(placement.protocol).toBe("whipplescript.exec.placement/v2");
      expect(placement.selected).toEqual(command.selected);
      expect(placement.envelope).toEqual(command.envelope);
      expect(placement.container_id).toBe((original as { served_by: string }).served_by);
      expect(placement.dispatch_id).toBe((original as { dispatch_header: string }).dispatch_header);
      expect(placement.dispatch_id).toBeTruthy();
      expect(placed[0].placement_json).not.toContain("executor-token");
    });
    const altered = structuredClone(command);
    altered.envelope.dispatch.stdin.original = false;
    await expect(invoke(altered)).rejects.toThrow();
    const retry = await invocationRequest("concurrent", "explicit-retry");
    const next = await (await invoke(retry)).json();
    expect(next).not.toEqual(original);
    expect(await executorCalls("concurrent")).toBe(2);
    expect((next as { dispatch_header: string }).dispatch_header).not.toBe((original as { dispatch_header: string }).dispatch_header);
  });

  it("recovers a controller completion after the broker write fails without restarting or redispatching", async () => {
    const command = await invocationRequest("failed-completion");
    // Initialize the broker before installing the write-failure fixture.
    await (await brokerStub().fetch("http://executor/exec", execRequest())).arrayBuffer();
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      state.storage.sql.exec("CREATE TRIGGER fail_receipt_completion BEFORE UPDATE ON exec_provider_receipts_v1 BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END");
    });
    await expect(invoke(command)).rejects.toThrow();
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      state.storage.sql.exec("DROP TRIGGER fail_receipt_completion");
      const rows = state.storage.sql.exec<{ receipt_json: string }>("SELECT receipt_json FROM exec_provider_receipts_v1 WHERE json_extract(invocation, '$[1].effect_id') = 'failed-completion'").toArray();
      expect(rows).toHaveLength(1);
      expect(JSON.parse(rows[0].receipt_json).state).toBe("started");
    });
    const containerName = await runInDurableObject(brokerStub(), async (_instance, state) => {
      const row = state.storage.sql.exec<{ placement_json: string }>("SELECT placement_json FROM exec_provider_placements_v1 WHERE json_extract(invocation, '$[1].effect_id') = 'failed-completion'").one();
      return JSON.parse(row.placement_json).container_id as string;
    });
    const namespace = (env as BrokerTestEnv).EXECUTOR;
    const executor = namespace.get(namespace.idFromName(containerName));
    const original = await runInDurableObject(executor, async (_instance, state) => {
      const row = state.storage.sql.exec<{ record_json: string }>("SELECT record_json FROM exec_controller_records_v1 WHERE json_extract(record_json, '$.placement.selected.effect_id') = 'failed-completion'").one();
      const record = JSON.parse(row.record_json);
      expect(record.state.state).toBe("completed");
      // Simulate the process disappearing; status recovery must use SQLite.
      state.storage.sql.exec("DELETE FROM executor_test_process");
      return record.state.body;
    });
    await evictDurableObject(executor);
    await evictDurableObject(brokerStub());
    const recovered = await invoke(command);
    const recoveredBody = await recovered.json();
    expect(recovered.status).toBe(200);
    expect(recoveredBody).toEqual(original);
    await runInDurableObject(executor, async (_instance, state) => {
      expect(state.storage.sql.exec("SELECT incarnation FROM executor_test_process").toArray()).toEqual([]);
    });
    expect(await executorCalls("failed-completion")).toBe(1);
    await runInDurableObject(brokerStub(), async (_instance, state) => {
      const row = state.storage.sql.exec<{ placement_json: string }>("SELECT placement_json FROM exec_provider_placements_v1 WHERE json_extract(invocation, '$[1].effect_id') = 'failed-completion'").one();
      const placement = JSON.parse(row.placement_json);
      expect(placement.protocol).toBe("whipplescript.exec.placement/v2");
      expect(placement.selected).toEqual(command.selected);
      expect(placement.envelope).toEqual(command.envelope);
      expect(placement.container_id).toMatch(/^instance-[0-3]$/);
      expect(placement.dispatch_id).toBeTruthy();
    });
  });
});

function reconcile(command: unknown, operation: unknown) {
  return brokerStub().fetch("http://executor/exec/reconcile", {
    method: "POST", headers: { authorization: "Bearer executor-token", "content-type": "application/json" },
    body: JSON.stringify({ ...command as object, operation }),
  });
}

async function providerState(command: Awaited<ReturnType<typeof invocationRequest>>) {
  return runInDurableObject(brokerStub(), async (_instance, state) => {
    const key = JSON.parse(bindings.exec_provider_claim(JSON.stringify(command.selected),JSON.stringify(command.envelope))).storage_key;
    const row = state.storage.sql.exec<{ receipt_json: string; placement_json: string }>(
      "SELECT receipt_json, placement_json FROM exec_provider_receipts_v1 JOIN exec_provider_placements_v1 USING(invocation) WHERE invocation = ?", key,
    ).toArray()[0];
    const resolution = state.storage.sql.exec<{ resolution_json: string }>("SELECT resolution_json FROM exec_provider_resolutions_v1 WHERE invocation = ?", key).toArray()[0]?.resolution_json;
    return { key, receipt: row && JSON.parse(row.receipt_json), placement: row && JSON.parse(row.placement_json), resolution: resolution && JSON.parse(resolution) };
  });
}

function executorStub(owner: string) {
  const namespace = (env as BrokerTestEnv).EXECUTOR;
  return namespace.get(namespace.idFromName(owner));
}

describe("provider lifetime reconciliation", () => {
  it("recovers proof for completed receipts without changing output or dispatching again", async () => {
    const command = await invocationRequest("provider-completed-proof");
    const original = await (await invoke(command)).json();
    const read = await reconcile(command,{ op:"read" });
    expect(read.status).toBe(200);
    const unproved = await read.json() as any;
    expect(unproved.lifetime).toEqual({ state:"pending" });
    expect(unproved.outcome).toEqual({ state:"completed",status:200,body:original });
    const fenced = await reconcile(command,{ op:"fence",fence_id:"provider-fence" });
    expect(fenced.status).toBe(200);
    const proof = await fenced.json() as any;
    expect(proof.lifetime).toMatchObject({ state:"terminated",fence_id:"provider-fence" });
    expect(proof.lifetime.incarnation).toBeTruthy(); expect(proof.lifetime.barrier_id).toBeTruthy();
    expect(proof.outcome).toEqual(unproved.outcome);
    const saved = await providerState(command);
    expect(await runInDurableObject(executorStub(saved.placement.container_id), async (_instance,state) => state.storage.sql.exec<{n:number}>("SELECT COUNT(*) AS n FROM executor_test_process").one().n)).toBe(0);
    const starts = await runInDurableObject(executorStub(saved.placement.container_id), async (_instance,state) => state.storage.sql.exec<{n:number}>("SELECT COUNT(*) AS n FROM executor_test_starts").one().n);
    await evictDurableObject(brokerStub()); await evictDurableObject(executorStub(saved.placement.container_id));
    expect(await (await reconcile(command,{op:"read"})).json()).toEqual(proof);
    expect(await (await reconcile(command,{op:"fence",fence_id:"later"})).json()).toEqual(proof);
    expect(await (await invoke(command)).json()).toEqual(original);
    expect(await executorCalls(command.selected.effect_id)).toBe(1);
    expect(await runInDurableObject(executorStub(saved.placement.container_id), async (_instance,state) => state.storage.sql.exec<{n:number}>("SELECT COUNT(*) AS n FROM executor_test_starts").one().n)).toBe(starts);
    expect((await providerState(command)).receipt).toEqual(saved.receipt);
  });

  it("requires durable fence intent before controller I/O and refuses caller proof", async () => {
    const command = await invocationRequest("provider-intent-first");
    const original = await (await invoke(command)).json();
    const placed = (await providerState(command)).placement;
    // This is a structurally valid, exactly bound forgery. Only the private
    // transport response, never a caller's body, may enter the observe seam.
    const rejected = await reconcile(command,{op:"observe",response:{
      protocol:"whipplescript.exec.controller.response/v1", placement:placed,
      action:{action:"replay",status:200,body:original,termination:{incarnation:"forged",fence_id:"forged",barrier_id:"forged"}},
    }});
    await rejected.arrayBuffer();
    expect(rejected.status).toBe(400);
    await runInDurableObject(brokerStub(),async (_instance,state) => {
      state.storage.sql.exec("CREATE TRIGGER fail_lifetime_intent AFTER INSERT ON exec_provider_resolutions_v1 BEGIN SELECT RAISE(ABORT,'intent failed'); END");
    });
    try { await expect(reconcile(command,{op:"fence",fence_id:"intent"})).rejects.toThrow(); }
    finally { await runInDurableObject(brokerStub(),async (_instance,state) => {state.storage.sql.exec("DROP TRIGGER fail_lifetime_intent");}); }
    for (const [table, event, message] of [
      ["exec_provider_resolutions_v1", "INSERT", "executor lifetime retention did not commit its record"],
      ["exec_provider_receipts_v1", "UPDATE", "executor lifetime retention lost its receipt"],
    ]) {
      await runInDurableObject(brokerStub(),async (_instance,state) => {
        state.storage.sql.exec(`CREATE TRIGGER ignore_lifetime_write BEFORE ${event} ON ${table} BEGIN SELECT RAISE(IGNORE); END`);
      });
      try { await expect(reconcile(command,{op:"fence",fence_id:"intent"})).rejects.toThrow(message); }
      finally { await runInDurableObject(brokerStub(),async (_instance,state) => {state.storage.sql.exec("DROP TRIGGER ignore_lifetime_write");}); }
      expect((await providerState(command)).resolution).toBeUndefined();
    }
    const saved = await providerState(command);
    expect(saved.resolution).toBeUndefined();
    const action = await executorStub(saved.placement.container_id).fetch("http://container/exec/controller/read",{method:"POST",body:JSON.stringify({placement:saved.placement})});
    expect((await action.json() as any).action.termination).toBeUndefined();
    expect((await (await reconcile(command,{op:"fence",fence_id:"intent"})).json() as any).lifetime.state).toBe("terminated");
  });

  it("rolls back output and proof together and recovers after broker eviction", async () => {
    const command = await invocationRequest("provider-proof-rollback");
    const original = await (await invoke(command)).json();
    await runInDurableObject(brokerStub(),async (_instance,state) => {
      const claim=JSON.parse(bindings.exec_provider_claim(JSON.stringify(command.selected),JSON.stringify(command.envelope)));
      state.storage.sql.exec("UPDATE exec_provider_receipts_v1 SET receipt_json = ? WHERE invocation = ?",JSON.stringify(claim.decision.receipt),claim.storage_key);
      state.storage.sql.exec("CREATE TRIGGER fail_lifetime_receipt AFTER UPDATE ON exec_provider_receipts_v1 WHEN json_extract(NEW.receipt_json,'$.state') = 'completed' BEGIN SELECT RAISE(ABORT,'proof receipt failed'); END");
    });
    try { await expect(reconcile(command,{op:"fence",fence_id:"rollback"})).rejects.toThrow(); }
    finally { await runInDurableObject(brokerStub(),async (_instance,state) => {state.storage.sql.exec("DROP TRIGGER fail_lifetime_receipt");}); }
    const failed = await providerState(command);
    expect(failed.receipt.state).toBe("started");
    expect(failed.resolution.lifetime).toEqual({state:"pending"});
    expect(failed.resolution.requested_fence_id).toBe("rollback");
    await evictDurableObject(brokerStub());
    const recovered = await (await reconcile(command,{op:"fence",fence_id:"rollback"})).json() as any;
    expect(recovered.lifetime.state).toBe("terminated");
    expect(recovered.outcome).toEqual({state:"completed",status:200,body:original});
    expect(await executorCalls(command.selected.effect_id)).toBe(1);
  });

  it("fences an unadmitted placement without claiming absent work or inventing output", async () => {
    const command = await invocationRequest("provider-never-admitted");
    await expect(reconcile(command,{op:"read"})).rejects.toThrow();
    expect((await providerState(command)).receipt).toBeUndefined();
    await runInDurableObject(brokerStub(),async (_instance,state) => {
      const selected=JSON.stringify(command.selected), envelope=JSON.stringify(command.envelope);
      const claim=JSON.parse(bindings.exec_provider_claim(selected,envelope));
      const receipt=JSON.stringify(claim.decision.receipt);
      const placed=bindings.exec_controller_place(selected,envelope,receipt,undefined,"instance-0","never-sent");
      state.storage.sql.exec("INSERT INTO exec_provider_receipts_v1 VALUES (?,?)",claim.storage_key,receipt);
      state.storage.sql.exec("INSERT INTO exec_provider_placements_v1 VALUES (?,?)",claim.storage_key,placed);
    });
    const proof=await (await reconcile(command,{op:"fence",fence_id:"never"})).json() as any;
    expect(proof.lifetime).toEqual({state:"not_admitted",fence_id:"never"});
    expect(proof.outcome).toEqual({state:"not_executed"});
    const pending = await invoke(command);
    await pending.arrayBuffer();
    expect(pending.status).toBe(202);
    expect(await executorCalls(command.selected.effect_id)).toBe(0);
  });

  it("reports admitted work with no retained result as uncertain after fencing", async () => {
    const command = await invocationRequest("provider-uncertain");
    await runInDurableObject(brokerStub(),async (_instance,state) => {
      const selected=JSON.stringify(command.selected),envelope=JSON.stringify(command.envelope);
      const claim=JSON.parse(bindings.exec_provider_claim(selected,envelope));
      const receipt=JSON.stringify(claim.decision.receipt);
      const placed=bindings.exec_controller_place(selected,envelope,receipt,undefined,"instance-0","lost-result");
      state.storage.sql.exec("INSERT INTO exec_provider_receipts_v1 VALUES (?,?)",claim.storage_key,receipt);
      state.storage.sql.exec("INSERT INTO exec_provider_placements_v1 VALUES (?,?)",claim.storage_key,placed);
    });
    const saved=await providerState(command);
    await runInDurableObject(executorStub("instance-0"),async (_instance,state) => {
      state.storage.sql.exec("CREATE TABLE IF NOT EXISTS executor_test_process (incarnation TEXT)");
      state.storage.sql.exec("INSERT INTO executor_test_process VALUES ('process')");
      const c=new ExecutorController(state.storage,"instance-0",bindings.exec_controller_transition,{
        inspect:bindings.exec_barrier_inspect,begin:bindings.exec_barrier_begin,finish:bindings.exec_barrier_finish,
      });
      await expect(c.execute(JSON.stringify(saved.placement),"process",async () => { throw new Error("lost result"); })).rejects.toThrow("lost result");
    });
    const proof=await (await reconcile(command,{op:"fence",fence_id:"uncertain"})).json() as any;
    expect(proof.lifetime).toMatchObject({state:"terminated",incarnation:"process",fence_id:"uncertain"});
    expect(proof.outcome).toEqual({state:"uncertain"});
    await evictDurableObject(brokerStub());
    expect(await (await reconcile(command,{op:"read"})).json()).toEqual(proof);
    const pending = await invoke(command);
    await pending.arrayBuffer();
    expect(pending.status).toBe(202);
    expect(await executorCalls(command.selected.effect_id)).toBe(0);
  });

  it("resumes a sibling barrier before interpreting a different provider fence ID", async () => {
    const command = await invocationRequest("provider-sibling-recovery");
    const original=await (await invoke(command)).json();
    const saved=await providerState(command);
    await runInDurableObject(executorStub(saved.placement.container_id),async (_instance,state) => {
      const c=new ExecutorController(state.storage,saved.placement.container_id,bindings.exec_controller_transition,{
        inspect:bindings.exec_barrier_inspect,begin:bindings.exec_barrier_begin,finish:bindings.exec_barrier_finish,
      });
      c.beginBarrier();
      expect(c.gate().closing).toBe(true);
    });
    await evictDurableObject(executorStub(saved.placement.container_id));
    const proof=await (await reconcile(command,{op:"fence",fence_id:"different-provider-intent"})).json() as any;
    expect(proof.lifetime.state).toBe("terminated");
    expect(proof.lifetime.fence_id).toBe(proof.lifetime.barrier_id);
    expect(proof.outcome.body).toEqual(original);
    expect(await executorCalls(command.selected.effect_id)).toBe(1);
  });
});

// Legacy controller intent can exist before this provider's resolution record.
describe("provider fence migration", () => {
  it.each(["pending", "completed", "not_admitted"] as const)("joins the original %s fence after failed barrier creation", async mode => {
    const command = await invocationRequest("provider-old-fence-" + mode);
    let original: unknown;
    if (mode === "completed") original = await (await invoke(command)).json();
    else await runInDurableObject(brokerStub(), async (_instance,state) => {
      const selected=JSON.stringify(command.selected), envelope=JSON.stringify(command.envelope);
      const claim=JSON.parse(bindings.exec_provider_claim(selected,envelope));
      const receipt=JSON.stringify(claim.decision.receipt);
      const placed=bindings.exec_controller_place(selected,envelope,receipt,undefined,"instance-0","older-dispatch");
      state.storage.sql.exec("INSERT INTO exec_provider_receipts_v1 VALUES (?,?)",claim.storage_key,receipt);
      state.storage.sql.exec("INSERT INTO exec_provider_placements_v1 VALUES (?,?)",claim.storage_key,placed);
    });
    const saved=await providerState(command);
    expect(saved.resolution).toBeUndefined();
    await runInDurableObject(executorStub(saved.placement.container_id), async (_instance,state) => {
      const c=new ExecutorController(state.storage,saved.placement.container_id,bindings.exec_controller_transition,{
        inspect:bindings.exec_barrier_inspect,begin:bindings.exec_barrier_begin,finish:bindings.exec_barrier_finish,
      });
      if (mode === "pending") {
        state.storage.sql.exec("CREATE TABLE IF NOT EXISTS executor_test_process (incarnation TEXT)");
        state.storage.sql.exec("INSERT INTO executor_test_process VALUES ('older-process')");
        await expect(c.execute(JSON.stringify(saved.placement),"older-process",async()=>{throw new Error("lost response");})).rejects.toThrow("lost response");
      }
      c.fence(JSON.stringify(saved.placement),"older-controller-fence");
      if (mode !== "not_admitted") {
        state.storage.sql.exec("CREATE TRIGGER fail_old_begin BEFORE INSERT ON exec_controller_barrier_v1 BEGIN SELECT RAISE(ABORT,'older begin failed'); END");
        state.storage.sql.exec("CREATE TRIGGER fail_old_update BEFORE UPDATE ON exec_controller_barrier_v1 BEGIN SELECT RAISE(ABORT,'older begin failed'); END");
        try { expect(()=>c.beginBarrier()).toThrow("older begin failed"); }
        finally { state.storage.sql.exec("DROP TRIGGER fail_old_begin"); state.storage.sql.exec("DROP TRIGGER fail_old_update"); }
      }
      expect(c.gate().closing).toBe(false);
    });
    await evictDurableObject(brokerStub());
    await evictDurableObject(executorStub(saved.placement.container_id));
    const response=await reconcile(command,{op:"fence",fence_id:"new-provider-intent"});
    const proof=await response.json() as any;
    expect(response.status).toBe(200);
    expect(proof.lifetime.fence_id).toBe("older-controller-fence");
    if (mode !== "not_admitted") expect(await runInDurableObject(executorStub(saved.placement.container_id), async (_instance,state) => state.storage.sql.exec<{n:number}>("SELECT COUNT(*) AS n FROM executor_test_process").one().n)).toBe(0);
    expect(proof.lifetime.state).toBe(mode === "not_admitted" ? "not_admitted" : "terminated");
    expect(proof.outcome).toEqual(mode === "completed" ? {state:"completed",status:200,body:original} : {state:mode === "pending" ? "uncertain" : "not_executed"});
    expect((await providerState(command)).resolution.requested_fence_id).toBe("new-provider-intent");
    expect(await (await reconcile(command,{op:"read"})).json()).toEqual(proof);
    expect(await executorCalls(command.selected.effect_id)).toBe(mode === "completed" ? 1 : 0);
  });
});

async function executorStartCount(owner: string): Promise<number> {
  return runInDurableObject(executorStub(owner), async (_object,state) => {
    if (!state.storage.sql.exec("SELECT name FROM sqlite_master WHERE name='executor_test_starts'").toArray().length) return 0;
    return state.storage.sql.exec<{n:number}>("SELECT COUNT(*) AS n FROM executor_test_starts").one().n;
  });
}

describe("preplacement fencing", () => {
  it.each(["absent", "guarded"] as const)("closes %s custody without execution and refuses late handoff", async (initial) => {
    const command = await invocationRequest(`preplacement-${initial}`);
    const starts = await executorStartCount("instance-0");
    if (initial === "guarded") {
      await runInDurableObject(brokerStub(), async (_object,state) => {
        const claim = JSON.parse(bindings.exec_provider_claim(JSON.stringify(command.selected),JSON.stringify(command.envelope)));
        expect(claim.decision.receipt.placement_required).toBe(true);
        state.storage.sql.exec("INSERT INTO exec_provider_receipts_v1 VALUES (?,?)", claim.storage_key, JSON.stringify(claim.decision.receipt));
      });
    }
    const response = await reconcile(command, {op:"ensure_fence", fence_id:"first-fence"});
    const proof = await response.json() as any;
    expect(response.status).toBe(200);
    expect(proof.lifetime).toEqual({state:"not_admitted",fence_id:"first-fence"});
    expect(proof.outcome).toEqual({state:"not_executed"});
    expect(proof.placement.envelope).toEqual(command.envelope);
    expect(await executorCalls(command.selected.effect_id)).toBe(0);
    await evictDurableObject(brokerStub());
    await evictDurableObject(executorStub(proof.placement.container_id));
    const late = await invoke(command);
    await late.arrayBuffer();
    expect(late.status).toBe(202);
    expect(await (await reconcile(command, {op:"ensure_fence",fence_id:"later"})).json()).toEqual(proof);
    expect(await executorCalls(command.selected.effect_id)).toBe(0);
    expect(await executorStartCount(proof.placement.container_id)).toBe(starts);
  });

  it("keeps unmarked claims unresolved without upgrading their custody", async () => {
    const command = await invocationRequest("preplacement-legacy");
    await runInDurableObject(brokerStub(), async (_object,state) => {
      const claim = JSON.parse(bindings.exec_provider_claim(JSON.stringify(command.selected),JSON.stringify(command.envelope)));
      delete claim.decision.receipt.placement_required;
      state.storage.sql.exec("INSERT INTO exec_provider_receipts_v1 VALUES (?,?)",claim.storage_key,JSON.stringify(claim.decision.receipt));
    });
    await expect(reconcile(command,{op:"ensure_fence",fence_id:"cannot-upgrade"})).rejects.toThrow("no guarded custody");
    await runInDurableObject(brokerStub(), async (_object,state) => {
      expect(state.storage.sql.exec("SELECT * FROM exec_provider_placements_v1 WHERE json_extract(invocation,'$[1].effect_id')=?",command.selected.effect_id).toArray()).toHaveLength(0);
      expect(state.storage.sql.exec("SELECT * FROM exec_provider_resolutions_v1 WHERE json_extract(invocation,'$[1].effect_id')=?",command.selected.effect_id).toArray()).toHaveLength(0);
      const row = state.storage.sql.exec<{receipt_json:string}>("SELECT receipt_json FROM exec_provider_receipts_v1 WHERE json_extract(invocation,'$[1].effect_id')=?",command.selected.effect_id).one();
      expect(JSON.parse(row.receipt_json).placement_required).toBeUndefined();
    });
    expect(await executorCalls(command.selected.effect_id)).toBe(0);
  });

  it.each([
    ["exec_provider_receipts_v1", "ABORT"], ["exec_provider_receipts_v1", "IGNORE"],
    ["exec_provider_placements_v1", "ABORT"], ["exec_provider_placements_v1", "IGNORE"],
    ["exec_provider_resolutions_v1", "ABORT"], ["exec_provider_resolutions_v1", "IGNORE"],
  ])("rolls back all fence custody when %s uses %s", async (table, fault) => {
    const command = await invocationRequest(`preplacement-fault-${table}-${fault}`);
    await runInDurableObject(brokerStub(), async (_object,state) => {
      state.storage.sql.exec(`CREATE TRIGGER preplacement_fault BEFORE INSERT ON ${table} BEGIN SELECT RAISE(${fault === "ABORT" ? "ABORT, 'injected fence custody failure'" : "IGNORE"}); END`);
    });
    try {
      await expect(reconcile(command,{op:"ensure_fence",fence_id:"atomic"}).then(async r => {await r.arrayBuffer(); return r;})).rejects.toThrow();
      await runInDurableObject(brokerStub(), async (_object,state) => {
        for (const name of ["exec_provider_receipts_v1","exec_provider_placements_v1","exec_provider_resolutions_v1"]) {
          expect(state.storage.sql.exec(`SELECT * FROM ${name} WHERE json_extract(invocation,'$[1].effect_id')=?`,command.selected.effect_id).toArray(), name).toHaveLength(0);
        }
      });
      await runInDurableObject(executorStub("instance-0"), async (_object,state) => {
        expect(state.storage.sql.exec("SELECT * FROM exec_controller_records_v1 WHERE json_extract(record_json,'$.placement.selected.effect_id')=?",command.selected.effect_id).toArray()).toHaveLength(0);
      });
    } finally {
      await runInDurableObject(brokerStub(), async (_object,state) => {state.storage.sql.exec("DROP TRIGGER preplacement_fault");});
    }
    const closed = await reconcile(command,{op:"ensure_fence",fence_id:"atomic"});
    const proof = await closed.json() as any;
    expect(closed.status).toBe(200);
    expect(proof.lifetime.state).toBe("not_admitted");
    expect(await executorCalls(command.selected.effect_id)).toBe(0);
  });

  it("blocks the original scheduler continuation when fencing wins placement", async () => {
    const command = await invocationRequest("preplacement-racing-forward");
    await runInDurableObject(brokerStub(), async (object) => {
      const owner = object as unknown as {
        scheduler: {acquire(priority: unknown): Promise<unknown>};
        fetch(request: Request): Promise<Response>;
      };
      const acquire = owner.scheduler.acquire.bind(owner.scheduler);
      let entered!: () => void, release!: () => void;
      const acquired = new Promise<void>(resolve => {entered = resolve;});
      const resume = new Promise<void>(resolve => {release = resolve;});
      owner.scheduler.acquire = async priority => {
        const lease = await acquire(priority);
        entered();
        await resume;
        return lease;
      };
      const invocation = owner.fetch(new Request("http://executor/exec/invocation", {
        method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify(command),
      })).then(async response => {await response.arrayBuffer(); return {status:response.status};}, error => ({error:String(error)}));
      try {
        await acquired;
        const fenced = await owner.fetch(new Request("http://executor/exec/reconcile", {
          method:"POST", headers:{"content-type":"application/json"},
          body:JSON.stringify({...command, operation:{op:"ensure_fence",fence_id:"race-winner"}}),
        }));
        const proof = await fenced.json() as any;
        expect(proof.lifetime).toEqual({state:"not_admitted",fence_id:"race-winner"});
        release();
        expect(await invocation).toEqual({error:expect.stringContaining("placement cannot be replaced")});
      } finally {
        release();
        owner.scheduler.acquire = acquire;
        await invocation;
      }
    });
    expect(await executorCalls(command.selected.effect_id)).toBe(0);
    const late = await invoke(command);
    await late.arrayBuffer();
    expect(late.status).toBe(202);
    expect(await executorCalls(command.selected.effect_id)).toBe(0);
  });
});
