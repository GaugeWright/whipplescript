import { ExecutorContainer } from "./index"; // Instantiate the real Rust/WASM reducer.
import * as bindings from "../pkg/whipplescript_host_do_bg.js";
import { env } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { ExecutorController } from "./executor-controller";
import { ExecutorControllerRoutes } from "./executor-controller-routes";

function stub(name: string) {
  const ns = (env as { EXECUTOR: DurableObjectNamespace }).EXECUTOR;
  return ns.get(ns.idFromName(name));
}

function controller(state: DurableObjectState) {
  if (!state.id.name) throw new Error("fixture requires a named controller");
  return new ExecutorController(state.storage, state.id.name, bindings.exec_controller_transition, {
      inspect: bindings.exec_barrier_inspect, begin: bindings.exec_barrier_begin, finish: bindings.exec_barrier_finish,
    });
}

async function placement(owner: string, attempt: string | null = null, dispatch?: unknown) {
  const selected = { instance_id: "controller-fixture", effect_id: owner, attempt_admission_event_id: attempt };
  const material = [selected.instance_id, selected.effect_id, "exec-run", ...(attempt === null ? [] : ["admission", attempt])].map(s => `${new TextEncoder().encode(s).length}:${s};`).join("");
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material)));
  const envelope = { protocol: "whipplescript.exec.invocation/v1", invocation: selected,
    run_id: "key_" + [...hash.slice(0, 16)].map(b => b.toString(16).padStart(2, "0")).join(""),
    dispatch: dispatch ?? { protocol: "whip-executor/1", effect_id: owner, stdin: { retained: true } },
  };
  const receipt = JSON.parse(bindings.exec_provider_claim(JSON.stringify(selected), JSON.stringify(envelope))).decision.receipt;
  return bindings.exec_controller_place(JSON.stringify(selected), JSON.stringify(envelope), JSON.stringify(receipt), undefined, owner, "dispatch-1");
}

function count(state: DurableObjectState) {
  return state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM exec_controller_records_v1").one().count;
}

describe("durable executor controller", () => {
  it("binds a fresh process to the retained protected invocation profile", async () => {
    const original = { engine: { kind: "cpython3147_wasi", artifact_path: "/opt/runtime.wasm", artifact_sha256: "a".repeat(64) },
      executable: "/usr/local/bin/whip", python_version: "3.14.7", environment: "original-epoch" };
    for (const fault of ["exact", "environment", "executable", "pin", "missing"]) {
      const owner = `controller-retained-runtime-${fault}`;
      const dispatch = { protocol: "whip-executor/1", effect_id: owner, argv: [original.executable, "executor", "observe-norm", "{script}"],
        stdin: { method_definition_json: JSON.stringify({ runtime: original, module: "main", function: "check", cases: [] }) } };
      const placed = await placement(owner, null, dispatch);
      await runInDurableObject(stub(owner), async (_instance, state) => {
        const c = controller(state); let starts = 0; let deliveries = 0; let probes = 0;
        const current = structuredClone(original);
        if (fault === "environment") current.environment = "new-epoch";
        if (fault === "executable") current.executable = "/new/whip";
        if (fault === "pin") current.engine.artifact_sha256 = "b".repeat(64);
        const routes = new ExecutorControllerRoutes(c, {
          runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read, delivery: bindings.exec_incarnation_delivery, result: bindings.exec_incarnation_result,
        }, async () => { starts++; }, async request => {
          const path = new URL(request.url).pathname;
          if (path === "/exec/incarnation") return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "current-process" });
          if (path === "/exec/norm-runtime") { probes++; return Response.json({ protocol: "whipplescript.exec.norm-runtime/v1", incarnation: "current-process", runtime: current }); }
          deliveries++; return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "current-process", status: 200, body: { original: true } });
        }, async () => {}, fault === "missing" ? undefined : { profile: JSON.stringify(current), verify: bindings.exec_norm_runtime_read });
        const request = (operation: string) => new Request(`http://container/exec/controller/${operation}`, { method: "POST", body: JSON.stringify({ placement: JSON.parse(placed) }) });
        await routes.fetch(request("read")); expect(starts).toBe(0); expect(probes).toBe(0);
        if (fault === "exact") {
          await routes.fetch(request("deliver")); expect(deliveries).toBe(1);
          await routes.fetch(request("deliver")); expect(deliveries).toBe(1); expect(starts).toBe(1); expect(probes).toBe(1);
          const cold = new ExecutorControllerRoutes(controller(state), {
            runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read, delivery: bindings.exec_incarnation_delivery, result: bindings.exec_incarnation_result,
          }, async () => { throw new Error("retained completion must not start"); }, async () => { throw new Error("retained completion must not probe"); });
          const replay = await cold.fetch(request("deliver"));
          expect((await replay.json() as { action: { action: string } }).action.action).toBe("replay");
          expect(starts).toBe(1); expect(probes).toBe(1); expect(deliveries).toBe(1);

        } else {
          await expect(routes.fetch(request("deliver"))).rejects.toThrow();
          expect(starts).toBe(0); expect(probes).toBe(0); expect(deliveries).toBe(0); expect(count(state)).toBe(0);
        }
      });
    }
  });

  it("requires the configured runtime proof from the admitted process", async () => {
    const profile = { engine: { kind: "cpython3147_wasi", artifact_path: "/opt/runtime.wasm", artifact_sha256: "a".repeat(64) },
      executable: "/usr/local/bin/whip", python_version: "3.14.7", environment: "norm-epoch" };
    for (const fault of ["exact", "missing", "stale", "changed", "malformed"]) {
      const owner = `controller-norm-runtime-${fault}`;
      const placed = await placement(owner);
      await runInDurableObject(stub(owner), async (_instance, state) => {
        const c = controller(state); let starts = 0; let deliveries = 0; let probes = 0;
        const routes = new ExecutorControllerRoutes(c, {
          runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read, delivery: bindings.exec_incarnation_delivery, result: bindings.exec_incarnation_result,
        }, async () => { starts++; }, async request => {
          const path = new URL(request.url).pathname;
          if (path === "/exec/incarnation") return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "process-one" });
          if (path === "/exec/norm-runtime") {
            probes++;
            if (fault === "missing") return Response.json({ protocol: "whipplescript.exec.norm-runtime/v1", incarnation: "process-one", runtime: profile }, { status: 409 });
            if (fault === "malformed") return Response.json({});
            return Response.json({ protocol: "whipplescript.exec.norm-runtime/v1", incarnation: fault === "stale" ? "process-two" : "process-one",
              runtime: fault === "changed" ? { ...profile, executable: "/changed" } : profile });
          }
          expect(path).toBe("/exec/bound"); deliveries++;
          return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "process-one", status: 200, body: { actual: false } });
        }, async () => {}, { profile: JSON.stringify(profile), verify: bindings.exec_norm_runtime_read });
        const request = (operation: string) => new Request(`http://container/exec/controller/${operation}`, {
          method: "POST", body: JSON.stringify({ placement: JSON.parse(placed) }),
        });
        await routes.fetch(request("read")); expect(starts).toBe(0); expect(probes).toBe(0);
        if (fault === "exact") {
          await routes.fetch(request("deliver")); expect(deliveries).toBe(1); expect(count(state)).toBe(1);
          await routes.fetch(request("deliver")); expect(starts).toBe(1); expect(probes).toBe(1); expect(deliveries).toBe(1);
        } else {
          await expect(routes.fetch(request("deliver"))).rejects.toThrow();
          expect(deliveries).toBe(0); expect(count(state)).toBe(0); expect(c.read(placed).action).toBe("absent");
        }
        expect(starts).toBe(1); expect(probes).toBe(1);
      });
    }
  });

  it("validates an empty resumed fence before physical destruction", async () => {
    const owner="controller-invalid-resumed-fence";
    const placed=await placement(owner);
    await runInDurableObject(stub(owner), async (_instance,state) => {
      const c=controller(state);
      await c.execute(placed,"process",async()=>({status:200,body:{stdout:"retained"}}));
      c.fence(placed,"original"); c.beginBarrier();
      let destroyed=0;
      const routes=new ExecutorControllerRoutes(c,{
        runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read, delivery:bindings.exec_incarnation_delivery, result:bindings.exec_incarnation_result,
      },async()=>{throw new Error("must not start");},async()=>{throw new Error("must not dispatch");},async()=>{destroyed++;});
      const request=(id:string)=>new Request("http://container/exec/controller/fence",{method:"POST",body:JSON.stringify({placement:JSON.parse(placed),fence_id:id})});
      await expect(routes.fetch(request(""))).rejects.toThrow("controller fence identity is empty");
      expect(destroyed).toBe(0); expect(c.gate().closing).toBe(true);
      const proof=await (await routes.fetch(request("new-request"))).json() as any;
      expect(proof.action.termination.fence_id).toBe("original");
      expect(proof.action.body).toEqual({stdout:"retained"});
      expect(destroyed).toBe(1); expect(c.gate().closing).toBe(false);
    });
  });

  it("commits sibling fences atomically and resumes the barrier after eviction", async () => {
    const owner = "controller-barrier-storage";
    const a = await placement(owner);
    const b = await placement(owner, "retry-b");
    let barrierId = "";
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      for (const placed of [a,b]) await expect(c.execute(placed,"process-1",async () => { throw new Error("lost transport"); })).rejects.toThrow();
      c.fence(a,"requested");
      state.storage.sql.exec("CREATE TRIGGER fail_barrier_begin AFTER INSERT ON exec_controller_barrier_v1 BEGIN SELECT RAISE(ABORT, 'barrier begin failed'); END");
      try { expect(() => c.beginBarrier()).toThrow(); }
      finally { state.storage.sql.exec("DROP TRIGGER fail_barrier_begin"); }
      expect(c.gate()).toEqual({ generation:"0", closing:false, barrier_id:null });
      expect(c.read(b)).toEqual({ action:"pending", incarnation:"process-1" });
      state.storage.sql.exec("CREATE TRIGGER ignore_barrier_target BEFORE UPDATE ON exec_controller_records_v1 BEGIN SELECT RAISE(IGNORE); END");
      try { expect(() => c.beginBarrier()).toThrow("controller barrier target disappeared during commit"); }
      finally { state.storage.sql.exec("DROP TRIGGER ignore_barrier_target"); }
      expect(c.gate().closing).toBe(false);
      const gate = c.beginBarrier();
      expect(gate.closing).toBe(true);
      barrierId = gate.barrier_id!;
      expect(c.read(b)).toEqual({ action:"fence_required", incarnation:"process-1", fence_id:barrierId });
    });
    await evictDurableObject(stub(owner));
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      expect(c.beginBarrier().barrier_id).toBe(barrierId);
      state.storage.sql.exec("CREATE TRIGGER fail_barrier_finish AFTER UPDATE ON exec_controller_barrier_v1 BEGIN SELECT RAISE(ABORT, 'barrier finish failed'); END");
      try { expect(() => c.finishBarrier(barrierId)).toThrow(); }
      finally { state.storage.sql.exec("DROP TRIGGER fail_barrier_finish"); }
      expect(c.gate().closing).toBe(true);
      expect(c.read(a).action).toBe("fence_required");
      c.finishBarrier(barrierId); // Storage fixture supplies the completed host boundary.
      expect(c.gate()).toEqual({ generation:"1", closing:false, barrier_id:barrierId });
      expect(c.read(a)).toEqual({ action:"terminated",incarnation:"process-1",fence_id:"requested",barrier_id:barrierId });
      expect(c.read(b)).toEqual({ action:"terminated",incarnation:"process-1",fence_id:barrierId,barrier_id:barrierId });
    });
  });

  it("refuses a barrier over a record stored under a substituted invocation key", async () => {
    const owner = "controller-barrier-key";
    const placed = await placement(owner);
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      await expect(c.execute(placed, "p", async () => { throw new Error("lost"); })).rejects.toThrow();
      state.storage.sql.exec("UPDATE exec_controller_records_v1 SET invocation = 'substituted'");
      expect(() => c.beginBarrier()).toThrow("controller inventory storage key changed");
      expect(c.gate()).toEqual({ generation: "0", closing: false, barrier_id: null });
    });
  });

  it("drains startup and legacy work before destruction and preserves a racing completion", async () => {
    const owner = "controller-barrier-order";
    const placed = await placement(owner);
    await runInDurableObject(stub(owner), async (_instance,state) => {
      const c=controller(state); const events:string[]=[];
      let releaseResult!: (response:Response)=>void;
      let started!:()=>void; const executing=new Promise<void>(resolve=>{started=resolve;});
      let legacyStarted!:()=>void; const legacyReady=new Promise<void>(resolve=>{legacyStarted=resolve;});
      let allowDestroy!:()=>void; const destruction=new Promise<void>(resolve=>{allowDestroy=resolve;});
      let atDestroy!:()=>void; const destroying=new Promise<void>(resolve=>{atDestroy=resolve;});
      const routes=new ExecutorControllerRoutes(c,{
        runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read,delivery:bindings.exec_incarnation_delivery,result:bindings.exec_incarnation_result,
      },async()=>{},async request=>{
        if(new URL(request.url).pathname==="/exec/incarnation") return Response.json({protocol:"whipplescript.exec.incarnation/v1",incarnation:"p"});
        started(); return new Promise<Response>(resolve=>{releaseResult=resolve;});
      },async()=>{
        events.push("destroy"); atDestroy(); await destruction;
        releaseResult(Response.json({protocol:"whipplescript.exec.incarnation/v1",incarnation:"p",status:200,body:{original:true}}));
      });
      const delivery=routes.fetch(new Request("http://container/exec/controller/deliver",{method:"POST",body:JSON.stringify({placement:JSON.parse(placed)})}));
      await executing;
      const legacy=routes.legacy(new Request("http://container/exec",{method:"POST",body:"{}"}),request=>new Promise<Response>((_resolve,reject)=>{
        request.signal.addEventListener("abort",()=>{events.push("legacy-drained");reject(request.signal.reason);},{once:true}); legacyStarted();
      })).catch(error=>String(error));
      await legacyReady;
      let acknowledged=false;
      const fence=routes.fetch(new Request("http://container/exec/controller/fence",{method:"POST",body:JSON.stringify({placement:JSON.parse(placed),fence_id:"f"})})).then(response=>{acknowledged=true;return response;});
      await destroying;
      expect(events).toEqual(["legacy-drained","destroy"]);
      expect(acknowledged).toBe(false);
      expect(c.gate().closing).toBe(true);
      const refused=await routes.legacy(new Request("http://container/exec"),async()=>{throw new Error("legacy escaped barrier");});
      expect(refused.status).toBe(503); await refused.arrayBuffer();
      allowDestroy();
      const result=await fence;
      expect((await result.json() as {action:unknown}).action).toEqual({action:"replay",status:200,body:{original:true},termination:{incarnation:"p",fence_id:"f",barrier_id:c.gate().barrier_id}});
      await (await delivery).arrayBuffer(); await legacy;
      expect(c.gate().closing).toBe(false);
    });
  });

  it("aborts pending startup before destruction and rejects a stale handshake after release", async () => {
    const owner="controller-barrier-startup";
    const target=await placement(owner); const startup=await placement(owner,"startup");
    const target2=await placement(owner,"target2"); const handshake=await placement(owner,"handshake");
    await runInDurableObject(stub(owner),async(_instance,state)=>{
      const c=controller(state); const events:string[]=[]; let starts=0; let boundCalls=0;
      let entered!:()=>void; const startupReady=new Promise<void>(resolve=>{entered=resolve;});
      let healthEntered!:()=>void; const healthReady=new Promise<void>(resolve=>{healthEntered=resolve;});
      let releaseHealth!:(response:Response)=>void;
      const routes=new ExecutorControllerRoutes(c,{runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read,delivery:bindings.exec_incarnation_delivery,result:bindings.exec_incarnation_result},signal=>{
        starts++;
        if(starts!==1) return Promise.resolve();
        return new Promise<void>((_resolve,reject)=>{signal.addEventListener("abort",()=>{events.push("startup-drained");reject(signal.reason);},{once:true});entered();});
      },async request=>{
        if(new URL(request.url).pathname==="/exec/incarnation") { healthEntered(); return new Promise<Response>(resolve=>{releaseHealth=resolve;}); }
        boundCalls++; throw new Error("stale handshake must not dispatch");
      },async()=>{events.push("destroy");});
      const request=(operation:string,placed:string)=>new Request(`http://container/exec/controller/${operation}`,{method:"POST",body:JSON.stringify({placement:JSON.parse(placed),fence_id:"f"})});
      await expect(c.execute(target,"p",async()=>{throw new Error("lost");})).rejects.toThrow();
      const pending=routes.fetch(request("deliver",startup)).catch(error=>String(error));
      await startupReady;
      await (await routes.fetch(request("fence",target))).arrayBuffer();
      expect(await pending).toContain("termination barrier");
      expect(events).toEqual(["startup-drained","destroy"]);
      expect(c.read(startup).action).toBe("absent");
      await expect(c.execute(target2,"p2",async()=>{throw new Error("lost");})).rejects.toThrow();
      const delayed=routes.fetch(request("deliver",handshake)); await healthReady;
      await (await routes.fetch(request("fence",target2))).arrayBuffer();
      expect(c.gate().generation).toBe("2");
      releaseHealth(Response.json({protocol:"whipplescript.exec.incarnation/v1",incarnation:"p2"}));
      const response=await delayed;
      expect((await response.json() as {action:{action:string}}).action.action).toBe("blocked");
      expect(boundCalls).toBe(0); expect(c.read(handshake).action).toBe("absent");
    });
  });

  it("keeps failed destruction fenced and resumes it on a fresh handle", async () => {
    const owner="controller-barrier-cold"; const placed=await placement(owner);
    let barrierId="";
    await runInDurableObject(stub(owner),async(_instance,state)=>{
      const c=controller(state);
      await expect(c.execute(placed,"p",async()=>{throw new Error("lost");})).rejects.toThrow();
      const routes=new ExecutorControllerRoutes(c,{runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read,delivery:bindings.exec_incarnation_delivery,result:bindings.exec_incarnation_result},async()=>{throw new Error("must not start");},async()=>{throw new Error("must not fetch");},async()=>{throw new Error("destroy failed");});
      await expect(routes.fetch(new Request("http://container/exec/controller/fence",{method:"POST",body:JSON.stringify({placement:JSON.parse(placed),fence_id:"f"})}))).rejects.toThrow("destroy failed");
      expect(c.read(placed).action).toBe("fence_required"); barrierId=c.gate().barrier_id!;
    });
    await evictDurableObject(stub(owner));
    await runInDurableObject(stub(owner),async(_instance,state)=>{
      const c=controller(state); let destroyed=0;
      const routes=new ExecutorControllerRoutes(c,{runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read,delivery:bindings.exec_incarnation_delivery,result:bindings.exec_incarnation_result},async()=>{throw new Error("must not start");},async()=>{throw new Error("must not fetch");},async()=>{destroyed++;});
      const response=await routes.fetch(new Request("http://container/exec/controller/fence",{method:"POST",body:JSON.stringify({placement:JSON.parse(placed),fence_id:"f"})}));
      expect((await response.json() as {action:unknown}).action).toEqual({action:"terminated",incarnation:"p",fence_id:"f",barrier_id:barrierId});
      expect(destroyed).toBe(1); expect(c.gate().generation).toBe("1");
    });
  });

  it("resumes a cold barrier before a fresh delivery starts a replacement", async () => {
    const owner = "controller-barrier-fresh";
    const old = await placement(owner);
    const fresh = await placement(owner, "fresh");
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      await expect(c.execute(old, "old-process", async () => { throw new Error("lost"); })).rejects.toThrow();
      c.fence(old, "f");
      expect(c.beginBarrier().closing).toBe(true);
    });
    await evictDurableObject(stub(owner));
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      const events: string[] = [];
      const routes = new ExecutorControllerRoutes(c, {
        runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read,
        delivery: bindings.exec_incarnation_delivery,
        result: bindings.exec_incarnation_result,
      }, async () => {
        expect(c.gate().closing).toBe(false);
        expect(c.read(old).action).toBe("terminated");
        events.push("start");
      }, async request => new URL(request.url).pathname === "/exec/incarnation"
        ? Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "new-process" })
        : Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "new-process", status: 200, body: { fresh: true } }),
      async () => { events.push("destroy"); });
      const response = await routes.fetch(new Request("http://container/exec/controller/deliver", {
        method: "POST", body: JSON.stringify({ placement: JSON.parse(fresh) }),
      }));
      expect((await response.json() as { action: unknown }).action).toEqual({ action: "replay", status: 200, body: { fresh: true } });
      expect(events).toEqual(["destroy", "start"]);
    });
  });

  it("atomically attaches termination proof without replacing completed sibling results", async () => {
    const owner = "controller-completed-lifetime";
    const a = await placement(owner); const b = await placement(owner, "sibling");
    const output = { action: "replay", status: 200, body: { timed_out: true, stdout: "retained" } };
    const request = () => new Request("http://container/exec/controller/fence", {
      method: "POST", body: JSON.stringify({ placement: JSON.parse(a), fence_id: "completed-fence" }),
    });
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      for (const p of [a, b]) expect(await c.execute(p, "p", async () => ({ status: output.status, body: output.body }))).toEqual(output);
      let destroyed = 0;
      const routes = new ExecutorControllerRoutes(c, {
        runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read, delivery: bindings.exec_incarnation_delivery, result: bindings.exec_incarnation_result,
      }, async () => { throw new Error("completed fence must not start"); }, async () => { throw new Error("completed fence must not dispatch"); }, async () => {
        destroyed++;
        expect(c.read(a)).toEqual(output); expect(c.read(b)).toEqual(output);
        expect(c.gate().closing).toBe(true);
      });
      state.storage.sql.exec("CREATE TRIGGER fail_completion_proof AFTER UPDATE ON exec_controller_barrier_v1 BEGIN SELECT RAISE(ABORT, 'completion proof failed'); END");
      try { await expect(routes.fetch(request())).rejects.toThrow("completion proof failed"); }
      finally { state.storage.sql.exec("DROP TRIGGER fail_completion_proof"); }
      expect(destroyed).toBe(1);
      expect(c.read(a)).toEqual(output); expect(c.read(b)).toEqual(output);
      expect(c.gate().closing).toBe(true);
    });
    await evictDurableObject(stub(owner));
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state); let destroyed = 0;
      const routes = new ExecutorControllerRoutes(c, {
        runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read, delivery: bindings.exec_incarnation_delivery, result: bindings.exec_incarnation_result,
      }, async () => { throw new Error("must not start"); }, async () => { throw new Error("must not dispatch"); }, async () => { destroyed++; });
      const response = await routes.fetch(request());
      const barrierId = c.gate().barrier_id;
      const expected = { ...output, termination: { incarnation: "p", fence_id: "completed-fence", barrier_id: barrierId } };
      expect((await response.json() as { action: unknown }).action).toEqual(expected);
      expect(c.read(b)).toEqual({ ...output, termination: { incarnation: "p", fence_id: barrierId, barrier_id: barrierId } });
      expect(await c.execute(a, "p", async () => { throw new Error("completed redispatch"); })).toEqual(expected);
      expect(destroyed).toBe(1); expect(c.gate().closing).toBe(false);
    });
  });

  it("wires the production container class to raw bound delivery and blocks direct bypass", async () => {
    const owner = "controller-production-class";
    const placed = JSON.parse(await placement(owner));
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const runtime = { engine: { kind: "cpython3147_wasi", artifact_path: "/opt/runtime.wasm", artifact_sha256: "a".repeat(64) },
        executable: "/usr/local/bin/whip", python_version: "3.14.7", environment: "norm-epoch" };
      const profile = JSON.stringify(runtime);
      const initializations: Promise<unknown>[] = [];
      const paths: string[] = [];
      let starts = 0;
      // Real production class and SDK initialization, with the physical port
      // replaced because workerd's test pool cannot run a container image.
      const savedContainer = Object.getOwnPropertyDescriptor(state, "container");
      const savedBlock = Object.getOwnPropertyDescriptor(state, "blockConcurrencyWhile");
      const block = state.blockConcurrencyWhile.bind(state);
      Object.defineProperty(state, "container", { configurable: true, value: {
          running: false,
          getTcpPort: (port: number) => {
            expect(port).toBe(8080);
            return { fetch: async (request: Request) => {
              const path = new URL(request.url).pathname;
              expect(request.headers.get("authorization")).toBe("Bearer production-fixture-token");
              paths.push(path);
              if (path === "/exec/incarnation") return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "process-1" });
              if (path === "/exec/norm-runtime") return Response.json({ protocol: "whipplescript.exec.norm-runtime/v1", incarnation: "process-1", runtime });
              expect(path).toBe("/exec/bound");
              expect(await request.json()).toEqual({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "process-1", dispatch: placed.envelope.dispatch });
              return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "process-1", status: 200, body: { original: true } });
            } };
          },
        } });
      Object.defineProperty(state, "blockConcurrencyWhile", { configurable: true, value: (callback: () => Promise<unknown>) => {
        const pending = block(callback); initializations.push(pending); return pending;
      } });
      try {
      const context = state as DurableObjectState<{}>;
      const request = (op: string) => new Request(`http://container/exec/controller/${op}`, { method: "POST", headers: { authorization: "Bearer production-fixture-token" }, body: JSON.stringify({ placement: placed }) });
      const unconfigured = new ExecutorContainer(context, {} as never);
      unconfigured.startAndWaitForPorts = async () => { starts++; };
      await Promise.all(initializations);
      await (await unconfigured.fetch(request("read"))).arrayBuffer();
      await expect(unconfigured.fetch(request("deliver"))).rejects.toThrow("executor startup requires WHIP_EXECUTOR_TOKEN");
      expect(starts).toBe(0);
      const executor = new ExecutorContainer(context, { WHIP_EXECUTOR_TOKEN: "production-fixture-token", WHIP_NORM_RUNTIME: profile } as never);
      expect(executor.envVars).toEqual({ WHIP_EXECUTOR_TOKEN: "production-fixture-token", WHIP_NORM_RUNTIME: profile });
      executor.startAndWaitForPorts = async () => { starts++; };
      executor.containerFetch = async () => { throw new Error("auto-starting transport must not be used"); };
      await Promise.all(initializations);
      await (await executor.fetch(request("read"))).arrayBuffer();
      expect(starts).toBe(0);
      expect(paths).toEqual([]);
      const response = await executor.fetch(request("deliver"));
      expect((await response.json() as { action: unknown }).action).toEqual({ action: "replay", status: 200, body: { original: true } });
      expect(starts).toBe(1);
      expect(paths).toEqual(["/exec/incarnation", "/exec/norm-runtime", "/exec/bound"]);
      await (await executor.fetch(request("read"))).arrayBuffer();
      expect(starts).toBe(1);
      expect(paths).toHaveLength(3);
      expect(state.storage.sql.exec<{ record_json: string }>("SELECT record_json FROM exec_controller_records_v1").one().record_json).not.toContain("production-fixture-token");
      for (const path of ["/exec/bound", "/exec/incarnation", "/exec/norm-runtime"]) {
        const refused = await executor.fetch(new Request(`http://container${path}`, { method: "POST", body: "{}" }));
        expect(refused.status).toBe(404);
        await refused.arrayBuffer();
      }
      } finally {
        // SDK initialization can schedule an alarm; this fixture's owning DO
        // is TestExecutor, so remove that SDK alarm before restoring its port.
        await Promise.allSettled(initializations);
        await state.storage.deleteAlarm();
        if (savedContainer) Object.defineProperty(state, "container", savedContainer);
        else Reflect.deleteProperty(state, "container");
        if (savedBlock) Object.defineProperty(state, "blockConcurrencyWhile", savedBlock);
        else Reflect.deleteProperty(state, "blockConcurrencyWhile");
      }
    });
  });

  it("routes read and pre-admission fence without starting a process", async () => {
    const owner = "controller-read-route";
    const placed = JSON.parse(await placement(owner));
    const invoke = async (operation: string, selected = placed) => {
      const response = await stub(owner).fetch(`http://container/exec/controller/${operation}`, {
        method: "POST", body: JSON.stringify({ placement: selected, fence_id: "fence-1" }),
      });
      return await response.json() as { action: { action: string } };
    };
    expect((await invoke("read")).action.action).toBe("absent");
    expect((await invoke("fence")).action.action).toBe("not_admitted");
    await evictDurableObject(stub(owner));
    expect((await invoke("deliver")).action.action).toBe("not_admitted");
    await expect(invoke("deliver", { ...placed, dispatch_id: "changed" })).rejects.toThrow();
    await runInDurableObject(stub(owner), async (_instance, state) => {
      expect(state.storage.sql.exec("SELECT name FROM sqlite_master WHERE name IN ('executor_test_process','executor_test_calls','executor_test_starts')").toArray()).toEqual([]);
    });
  });

  it("rechecks a fence after delayed startup before any process delivery", async () => {
    const owner = "controller-startup-race";
    const placed = await placement(owner);
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      let release!: () => void;
      const barrier = new Promise<void>(resolve => { release = resolve; });
      let markStarted!: () => void;
      const started = new Promise<void>(resolve => { markStarted = resolve; });
      let rawCalls = 0;
      const routes = new ExecutorControllerRoutes(c, {
        runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read, delivery: bindings.exec_incarnation_delivery, result: bindings.exec_incarnation_result,
      }, () => { markStarted(); return barrier; }, async () => { rawCalls++; throw new Error("fenced startup must not deliver"); });
      const delivery = routes.fetch(new Request("http://container/exec/controller/deliver", {
        method: "POST", body: JSON.stringify({ placement: JSON.parse(placed) }),
      }));
      await started;
      try { c.fence(placed, "fence-1"); }
      finally { release(); }
      const response = await delivery;
      expect((await response.json() as { action: { action: string } }).action.action).toBe("not_admitted");
      expect(rawCalls).toBe(0);
    });
  });

  it("refuses a changed process completion and preserves the admitted invocation", async () => {
    const owner = "controller-changed-process";
    const placed = await placement(owner);
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      let calls = 0;
      const routes = new ExecutorControllerRoutes(c, {
        runtime: bindings.exec_norm_runtime_prepare, read: bindings.exec_incarnation_read, delivery: bindings.exec_incarnation_delivery, result: bindings.exec_incarnation_result,
      }, async () => {}, async request => {
        if (new URL(request.url).pathname === "/exec/incarnation") return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "original" });
        calls++;
        expect(new URL(request.url).pathname).toBe("/exec/bound");
        expect(await request.json()).toEqual({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "original", dispatch: JSON.parse(placed).envelope.dispatch });
        return Response.json({ protocol: "whipplescript.exec.incarnation/v1", incarnation: "replacement", status: 200, body: { forged: true } });
      });
      await expect(routes.fetch(new Request("http://container/exec/controller/deliver", { method: "POST", body: JSON.stringify({ placement: JSON.parse(placed) }) }))).rejects.toThrow();
      expect(calls).toBe(1);
      expect(c.read(placed)).toEqual({ action: "pending", incarnation: "original" });
    });
    await evictDurableObject(stub(owner));
    const response = await stub(owner).fetch("http://container/exec/controller/deliver", { method: "POST", body: JSON.stringify({ placement: JSON.parse(placed) }) });
    expect((await response.json() as { action: unknown }).action).toEqual({ action: "pending", incarnation: "original" });
  });

  it("commits admission before I/O and leaves failed completion pending after eviction", async () => {
    const owner = "controller-write-failures";
    const placed = await placement(owner);
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      state.storage.sql.exec("CREATE TRIGGER fail_admission AFTER INSERT ON exec_controller_records_v1 BEGIN SELECT RAISE(ABORT, 'admission failed'); END");
      let calls = 0;
      const run = async () => { calls++; return { status: 200, body: { original: true } }; };
      try {
        await expect(c.execute(placed, "epoch-1", run)).rejects.toThrow();
        expect(calls).toBe(0);
        expect(count(state)).toBe(0);
      } finally { state.storage.sql.exec("DROP TRIGGER fail_admission"); }
      state.storage.sql.exec("CREATE TRIGGER fail_completion AFTER UPDATE ON exec_controller_records_v1 BEGIN SELECT RAISE(ABORT, 'completion failed'); END");
      try {
        await expect(c.execute(placed, "epoch-1", async dispatch => {
          expect(c.read(placed)).toEqual({ action: "pending", incarnation: "epoch-1" });
          expect(dispatch).toEqual(JSON.parse(placed).envelope.dispatch);
          return run();
        })).rejects.toThrow();
        expect(calls).toBe(1);
      } finally { state.storage.sql.exec("DROP TRIGGER fail_completion"); }
    });
    await evictDurableObject(stub(owner));
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      expect(await c.execute(placed, "epoch-1", async () => { throw new Error("must not redispatch"); }))
        .toEqual({ action: "pending", incarnation: "epoch-1" });
      expect(count(state)).toBe(1);
    });
  });

  it("retains a non-admission tombstone and refuses changed dispatch identity after eviction", async () => {
    const owner = "controller-tombstone";
    const placed = await placement(owner);
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      expect(c.read(placed)).toEqual({ action: "absent" });
      expect(count(state)).toBe(0);
      state.storage.sql.exec("CREATE TRIGGER fail_fence AFTER INSERT ON exec_controller_records_v1 BEGIN SELECT RAISE(ABORT, 'fence failed'); END");
      try {
        expect(() => c.fence(placed, "fence-1")).toThrow();
        expect(c.read(placed)).toEqual({ action: "absent" });
      } finally { state.storage.sql.exec("DROP TRIGGER fail_fence"); }
      expect(c.fence(placed, "fence-1")).toEqual({ action: "not_admitted", fence_id: "fence-1" });
    });
    await evictDurableObject(stub(owner));
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      expect(await c.execute(placed, "epoch-1", async () => { throw new Error("late execution"); }))
        .toEqual({ action: "not_admitted", fence_id: "fence-1" });
      const changed = { ...JSON.parse(placed), dispatch_id: "replacement" };
      expect(() => c.read(JSON.stringify(changed))).toThrow();
      expect(count(state)).toBe(1);
      // Reads must not rewrite even a differently formatted durable record.
      const row = state.storage.sql.exec<{ record_json: string }>("SELECT record_json FROM exec_controller_records_v1").one();
      const formatted = JSON.stringify(JSON.parse(row.record_json), null, 2);
      state.storage.sql.exec("UPDATE exec_controller_records_v1 SET record_json = ?", formatted);
      state.storage.sql.exec("CREATE TRIGGER forbid_read_write AFTER UPDATE ON exec_controller_records_v1 BEGIN SELECT RAISE(ABORT, 'read wrote'); END");
      try { expect(c.read(placed)).toEqual({ action: "not_admitted", fence_id: "fence-1" }); }
      finally { state.storage.sql.exec("DROP TRIGGER forbid_read_write"); }
    });
  });

  it("refuses foreign and legacy placements before I/O and retains transport loss", async () => {
    const owner = "controller-transport-loss";
    const placed = await placement(owner);
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      let calls = 0;
      for (const invalid of [
        { ...JSON.parse(placed), container_id: "foreign" },
        { ...JSON.parse(placed), protocol: "whipplescript.exec.placement/v1" },
      ]) {
        await expect(c.execute(JSON.stringify(invalid), "epoch-1", async () => {
          calls++; return { status: 200, body: {} };
        })).rejects.toThrow();
      }
      expect(calls).toBe(0);
      expect(count(state)).toBe(0);
      await expect(c.execute(placed, "epoch-1", async () => {
        calls++;
        throw new Error("lost response");
      })).rejects.toThrow("lost response");
      expect(calls).toBe(1);
    });
    await evictDurableObject(stub(owner));
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      expect(await c.execute(placed, "epoch-1", async () => { throw new Error("lost transport redispatch"); }))
        .toEqual({ action: "pending", incarnation: "epoch-1" });
    });
  });

  it("admits concurrent delivery once and retains completion over a pending fence", async () => {
    const owner = "controller-completion-race";
    const placed = await placement(owner);
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      let release!: () => void;
      const barrier = new Promise<void>(resolve => { release = resolve; });
      let calls = 0;
      const first = c.execute(placed, "epoch-1", async () => {
        calls++;
        await barrier;
        return { status: 503, body: { retained: "original" } };
      });
      try {
        expect(await c.execute(placed, "epoch-1", async () => { calls++; return { status: 200, body: {} }; }))
          .toEqual({ action: "pending", incarnation: "epoch-1" });
        expect(c.fence(placed, "fence-1")).toEqual({ action: "fence_required", incarnation: "epoch-1", fence_id: "fence-1" });
        expect(calls).toBe(1);
      } finally { release(); }
      expect(await first).toEqual({ action: "replay", status: 503, body: { retained: "original" } });
    });
    await evictDurableObject(stub(owner));
    await runInDurableObject(stub(owner), async (_instance, state) => {
      const c = controller(state);
      const expected = { action: "replay", status: 503, body: { retained: "original" } };
      expect(c.read(placed)).toEqual(expected);
      expect(c.fence(placed, "fence-1")).toEqual({ action: "fence_required", incarnation: "epoch-1", fence_id: "fence-1" });
      expect(() => c.fence(placed, "later-fence")).toThrow("controller completion fence cannot be replaced");
      expect(await c.execute(placed, "epoch-1", async () => { throw new Error("completed redispatch"); })).toEqual(expected);
    });
  });
});
