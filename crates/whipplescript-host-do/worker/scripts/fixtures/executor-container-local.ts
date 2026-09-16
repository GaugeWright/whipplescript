// Local-only physical fixture. The deep script binds Wrangler to loopback.
import { ExecutorContainer as ProductionExecutorContainer, WorkspaceBroker } from "../../src/index";
import * as bindings from "../../pkg/whipplescript_host_do_bg.js";

import { ExecutorController } from "../../src/executor-controller";
export { WorkspaceBroker };

// Only this loopback fixture can seed the crash window between retained intent
// and barrier creation. Every ordinary request delegates to the production class.
export class ExecutorContainer extends ProductionExecutorContainer {
  private readonly fixtureState: DurableObjectState;
  constructor(...args: ConstructorParameters<typeof ProductionExecutorContainer>) {
    super(...args);
    this.fixtureState = args[0];
  }
  override async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname !== "/fixture/older-intent") return super.fetch(request);
    const { placement } = await request.json() as { placement: unknown };
    const state = this.fixtureState;
    if (!state.id.name) throw new Error("fixture controller requires owner identity");
    const controller = new ExecutorController(state.storage, state.id.name, bindings.exec_controller_transition, {
      inspect: bindings.exec_barrier_inspect, begin: bindings.exec_barrier_begin, finish: bindings.exec_barrier_finish,
    });
    const intent = controller.fence(JSON.stringify(placement), "older-controller-fence");
    state.storage.sql.exec("CREATE TRIGGER fixture_failed_begin BEFORE INSERT ON exec_controller_barrier_v1 BEGIN SELECT RAISE(ABORT,'fixture begin failed'); END");
    state.storage.sql.exec("CREATE TRIGGER fixture_failed_update BEFORE UPDATE ON exec_controller_barrier_v1 BEGIN SELECT RAISE(ABORT,'fixture begin failed'); END");
    let refused = false;
    try { controller.beginBarrier(); }
    catch (error) {
      if (!String(error).includes("fixture begin failed")) throw error;
      refused = true;
    }
    finally {
      state.storage.sql.exec("DROP TRIGGER fixture_failed_begin");
      state.storage.sql.exec("DROP TRIGGER fixture_failed_update");
    }
    if (!refused || controller.gate().closing) throw new Error("fixture did not retain an older standalone intent");
    return Response.json({ intent, gate: controller.gate() });
  }
}

type Command = {
  operation: "intent" | "place" | "read" | "deliver" | "fence" | "provider-prepare" | "provider-invoke" | "provider-read" | "provider-fence" | "provider-ensure-fence";
  invocation: unknown;
  effect: string;
  dispatch: unknown;
  placement: unknown;
};

export default {
  async fetch(request: Request, env: { EXECUTOR: DurableObjectNamespace; WORKSPACE_BROKER: DurableObjectNamespace }) {
    const command = await request.json() as Command;
    const owner = "barrier-local-fixture";
    if (command.operation === "intent") {
      const placed = command.placement as { container_id: string };
      return env.EXECUTOR.get(env.EXECUTOR.idFromName(placed.container_id)).fetch(new Request("http://container/fixture/older-intent", {
        method: "POST", body: JSON.stringify({ placement: command.placement }),
      }));
    }
    if (command.operation === "place" || command.operation === "provider-prepare") {
      const selected = {
        instance_id: "barrier-local",
        effect_id: command.effect,
        attempt_admission_event_id: null,
      };
      const material = [selected.instance_id, selected.effect_id, "exec-run"]
        .map(value => `${new TextEncoder().encode(value).length}:${value};`).join("");
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material)));
      const envelope = {
        protocol: "whipplescript.exec.invocation/v1",
        invocation: selected,
        run_id: "key_" + [...hash.slice(0, 16)].map(byte => byte.toString(16).padStart(2, "0")).join(""),
        dispatch: command.dispatch,
      };
      if (command.operation === "provider-prepare") return Response.json({ selected, envelope });
      const receipt = JSON.parse(bindings.exec_provider_claim(
        JSON.stringify(selected), JSON.stringify(envelope),
      )).decision.receipt;
      return new Response(bindings.exec_controller_place(
        JSON.stringify(selected), JSON.stringify(envelope), JSON.stringify(receipt),
        undefined, owner, "dispatch-" + command.effect,
      ), { headers: { "content-type": "application/json" } });
    }
    if (command.operation.startsWith("provider-")) {
      const invoke = command.operation === "provider-invoke";
      return env.WORKSPACE_BROKER.get(env.WORKSPACE_BROKER.idFromName("workspace")).fetch(new Request(
        "http://broker/exec/" + (invoke ? "invocation" : "reconcile"), {
          method: "POST", headers: { authorization: "Bearer local-barrier-fixture" },
          body: JSON.stringify({ ...command.invocation as object, ...(invoke ? {} : {
            operation: command.operation === "provider-read" ? { op: "read" } : { op: command.operation === "provider-ensure-fence" ? "ensure_fence" : "fence", fence_id: "physical-provider-fence" },
          }) }),
        },
      ));
    }
    return env.EXECUTOR.get(env.EXECUTOR.idFromName(owner)).fetch(new Request(
      "http://container/exec/controller/" + command.operation,
      {
        method: "POST",
        headers: { authorization: "Bearer local-barrier-fixture" },
        body: JSON.stringify({ placement: command.placement, fence_id: "local-fence" }),
      },
    ));
  },
};
