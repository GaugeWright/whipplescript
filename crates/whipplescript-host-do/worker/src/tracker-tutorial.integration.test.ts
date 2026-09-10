import { env } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";
import { WasmDurableInstance } from "../pkg/whipplescript_host_do_bg.js";
import schema from "../do_schema.sql";
import source from "../../../../examples/gaugedesk-basics.whip?raw";
import type { TestEnv } from "./integration-helpers";

it("runs the ordinary Basics source through wasm and durable SQLite across eviction", async () => {
  const namespace = (env as unknown as TestEnv).WORKFLOW_INSTANCE;
  const stub = namespace.get(namespace.idFromName("basics-tutorial"));
  let identity: string | undefined;
  for (let step = 0; step <= 4; step++) {
    await runInDurableObject(stub, async (_object, state) => {
      const sql = state.storage.sql;
      if (step === 0) sql.exec(schema);
      const bridge = {
        atomic(body: () => void) { state.storage.transactionSync(body); },
        activity() {},
        exec(query: string, paramsJson: string) {
          return sql.exec(query, ...JSON.parse(paramsJson)).rowsWritten;
        },
        query(query: string, paramsJson: string) {
          return JSON.stringify([...sql.exec(query, ...JSON.parse(paramsJson))].map(Object.values));
        },
      };
      const instance = WasmDurableInstance.create(
        bridge, source, JSON.stringify({ learner: { authority: "person:learner" } }),
        "person:learner", undefined, undefined, undefined, undefined, undefined, undefined,
      );
      const outcome = JSON.parse(instance.step(undefined, Date.now()));
      const instances = [...sql.exec("SELECT instance_id FROM instances")];
      expect(instances).toHaveLength(1);
      identity ??= String(instances[0].instance_id);
      expect(instances[0].instance_id).toBe(identity);
      if (step === 4) {
        expect(outcome.kind).toBe("terminal");
        expect(instance.status()).toBe("completed");
      } else {
        expect(outcome.kind).toBe("parked");
        const issues = [...sql.exec("SELECT issue_id, status, assigned_to FROM tracker_issues WHERE queue = 'tutorials'")];
        expect(issues).toHaveLength(step + 1);
        const open = issues.filter(issue => issue.status === "open");
        expect(open).toHaveLength(1);
        expect(open[0].assigned_to).toBe("person:learner");
        // Supply a persisted closing as the external tracker actor. Store-level
        // finish/admission is covered in Rust; this test exercises its consumer
        // through the actual wasm bridge, workerd SQL, clock and eviction.
        sql.exec("UPDATE tracker_issues SET status = 'closed' WHERE issue_id = ?", open[0].issue_id);
        sql.exec(`INSERT INTO tracker_events (event_id, issue_id, kind, payload_json, actor)
          SELECT ?, content_id, 'issue.closed', '{}', 'person:learner'
          FROM tracker_aliases WHERE alias = ?`, `closing-${step}`, open[0].issue_id);
      }
      instance.free();
    });
    await evictDurableObject(stub);
  }
});
