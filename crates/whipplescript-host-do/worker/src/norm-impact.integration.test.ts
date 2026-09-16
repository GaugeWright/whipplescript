import { env, SELF, runInDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";

type Deployment = { planning: string; runtime: string; image_binding: string; deployed_image: string; time_basis: string };
type FixtureHost = {
  configureNormTestPublicBindings(keys: unknown[], restorations: unknown[]): void;
  configureNormTestPlanning(deployment: Partial<Deployment>): void;
};
type ResponseBody = { protocol: string; result: { plan: { time_basis: string; requirements: Record<string, Array<{work:{kind:string}}>> }; [key: string]: unknown } };
type Vector = {
  trust: { public_bindings: unknown[] }; checkpoint: unknown; events: unknown[];
  deployment: Deployment; request: {protocol:string;command:Record<string,unknown>};
  expected: ResponseBody; requirement: string; old_frontier: string[];
  runtime_rows: Array<{table:string;columns:string[];rows:Array<Array<string|number|null>>}>;
  artifacts: {blobs:Array<{id:string;body:string;byte_len:number}>;cuts:Array<{cut_id:string;change_id:string;branch_id:string;manifest_hash:string;recorded_at:string}>};
};

// norm-installed-impact: authenticated installed planning, refusals and journal immutability.
it("plans through the authenticated installed-image WASM door without mutating journals", async () => {
  const vectors = JSON.parse((env as unknown as {NORM_IMPACT_VECTOR:string}).NORM_IMPACT_VECTOR) as {cases:Vector[]};
  expect(vectors.cases).toHaveLength(2);
  const namespace = (env as unknown as {WORKFLOW_INSTANCE:DurableObjectNamespace}).WORKFLOW_INSTANCE;
  for (const [index, vector] of vectors.cases.entries()) {
    const id = namespace.idFromName(`tenant:norm-test:placement:impact-${index}`);
    const stub = namespace.get(id);
    const configure = (deployment: Partial<Deployment>) => runInDurableObject(stub, async object => {
      (object as unknown as FixtureHost).configureNormTestPlanning(deployment);
    });
    await runInDurableObject(stub, async object => {
      (object as unknown as FixtureHost).configureNormTestPublicBindings(vector.trust.public_bindings,
        [{object_id:id.toString(),checkpoint:vector.checkpoint}]);
    });
    const send = (operation: string, body: unknown, authorized = true) => SELF.fetch(
      `https://runtime.test/v1/tenants/norm-test/placements/impact-${index}/host/norm/${operation}`, {
        method:"POST", headers:{"content-type":"application/json", ...(authorized ? {authorization:"Bearer control-token"} : {})},
        body:JSON.stringify(body),
      });
    const refused = await send("impacts", vector.request, false);
    expect(refused.status).toBe(401); await refused.body?.cancel();
    const missing = await send("impacts", vector.request);
    expect(missing.status).toBe(503); await missing.body?.cancel();
    const provision = await send("provision", {});
    expect(provision.status).toBe(200); await provision.body?.cancel();
    const imported = await send("commands", {protocol:"whipplescript.norm.commands/v1",command:{kind:"import",events:vector.events}});
    expect(imported.status).toBe(200); await imported.body?.cancel();
    const absentCut = await send("commands", {protocol:"whipplescript.norm.commands/v1",command:{kind:"resources",point:{cut:"cut"}}});
    expect(absentCut.status).toBe(400);
    expect(await absentCut.text()).toContain("is not recorded");
    await runInDurableObject(stub, async (_object,state) => {
      for (const table of vector.runtime_rows) {
        expect(/^[a-z_][a-z0-9_]*$/.test(table.table)).toBe(true);
        for (const column of table.columns) expect(/^[a-z_][a-z0-9_]*$/.test(column)).toBe(true);
        for (const row of table.rows) state.storage.sql.exec(
          `INSERT INTO "${table.table}" (${table.columns.map(column => `"${column}"`).join(",")}) VALUES (${row.map(() => "?").join(",")})`, ...row);
      }
      for (const b of vector.artifacts.blobs) state.storage.sql.exec("INSERT INTO content_blobs (id,body,byte_len) VALUES (?,?,?)",b.id,b.body,b.byte_len);
      for (const c of vector.artifacts.cuts) state.storage.sql.exec("INSERT INTO cuts (cut_id,change_id,branch_id,manifest_hash,recorded_at) VALUES (?,?,?,?,?)",c.cut_id,c.change_id,c.branch_id,c.manifest_hash,c.recorded_at);
    });
    const snapshot = () => runInDurableObject(stub, async (_object,state) => ({
      runtime:state.storage.sql.exec("SELECT * FROM events ORDER BY sequence").toArray(),
      ledger:state.storage.sql.exec("SELECT * FROM tracker_events ORDER BY event_seq").toArray(),
      runs:state.storage.sql.exec("SELECT * FROM runs ORDER BY run_id").toArray(),
    }));
    const before = await snapshot();
    await configure(vector.deployment);
    for (let repeat = 0; repeat < 2; repeat++) {
      const result = await send("impacts", vector.request);
      const body = await result.json() as ResponseBody;
      expect(result.status, JSON.stringify(body)).toBe(200);
      expect(body.result.plan.time_basis).toMatch(/^hosted-impact\/\d+\/[0-9a-f-]+$/);
      const expected = JSON.parse(JSON.stringify(vector.expected), (key, value) =>
        key === "time_basis" && value === vector.deployment.time_basis ? body.result.plan.time_basis : value);
      expect(body).toEqual(expected);
    }
    const old = {...vector.request,command:{...vector.request.command,before_frontier:vector.old_frontier,after_frontier:vector.old_frontier}};
    const oldResponse = await send("impacts",old);
    const oldBody = await oldResponse.json() as ResponseBody;
    expect(oldResponse.status,JSON.stringify(oldBody)).toBe(200);
    expect(oldBody.result.plan.requirements[vector.requirement][0].work.kind).toBe("check");
    for (const field of ["planning","runtime","image_binding","deployed_image"] as const) {
      const missing = {...vector.deployment}; delete (missing as Partial<Deployment>)[field];
      await configure(missing);
      const result = await send("impacts",vector.request); expect(result.status).toBe(503); await result.body?.cancel();
    }
    for (const change of [
      {...vector.deployment,deployed_image:`sha256:${"d".repeat(64)}`},
      {...vector.deployment,runtime:JSON.stringify({...JSON.parse(vector.deployment.runtime),environment:"different"})},
      {...vector.deployment,image_binding:"{}"},
    ]) {
      await configure(change);
      const result = await send("impacts",vector.request); expect(result.status).toBe(400); await result.body?.cancel();
    }
    await configure(vector.deployment);
    for (const body of [
      {...vector.request,deployment:vector.deployment},
      {...vector.request,command:{...vector.request.command,image_binding:vector.deployment.image_binding}},
      {...vector.request,protocol:"caller"},
    ]) {
      const result = await send("impacts",body); expect(result.status).toBe(400); await result.body?.cancel();
    }
    const oversized = await send("impacts",{...vector.request,padding:"x".repeat(1024*1024)});
    expect(oversized.status).toBe(413); await oversized.body?.cancel();
    await runInDurableObject(stub,async (_object,state) => { state.storage.sql.exec("DELETE FROM cuts WHERE cut_id = 'cut'"); });
    const unavailable = await send("impacts",{...vector.request,command:{before_cut:"same-content",after_cut:"same-content"}});
    const unavailableBody = await unavailable.json() as ResponseBody;
    expect(unavailable.status,JSON.stringify(unavailableBody)).toBe(200);
    expect(unavailableBody.result.plan.requirements[vector.requirement][0].work.kind).toBe("verify_evidence");
    expect(await snapshot()).toEqual(before);
  }
});
