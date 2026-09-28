import { env, SELF, runInDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";

type Deployment = { planning: string; runtime: string; image_binding: string; deployed_image: string };
type FixtureHost = {
  configureNormTestPublicBindings(keys: unknown[], restorations: unknown[]): void;
  configureNormTestPlanning(deployment: Partial<Deployment>): void;
};
type Table = { table: string; ddl: string[]; columns: string[]; rows: Array<Array<string | number | null>> };
type Answer = { protocol: string; result: Record<string, unknown> & { detail?: { requirements: Record<string, string[]> } } };
type Vector = {
  protocol: string; public_bindings: unknown[]; checkpoint: unknown;
  events: unknown[]; supported_events: unknown[]; deployment: Deployment;
  workspace: Table[]; journal: Table[]; requirement: string; stream: string;
  path: string; base: string; candidate: string;
  refused: Answer["result"]; admitted: Answer["result"];
};

// norm-installed-promotion: the mainline gate through the authenticated
// installed-image WASM door. The object's workspace, runtime journal and
// ledger were written by the native hosted door's own codecs; this suite
// proves the Worker installs the same premises and answers the same way.
it("gates a stream's promotion onto the mainline through the installed-image WASM door", async () => {
  const vector = JSON.parse((env as unknown as { NORM_PROMOTION_VECTOR: string }).NORM_PROMOTION_VECTOR) as Vector;
  expect(vector.protocol).toBe("whipplescript.norm.promotion-test-vector/v1");
  const namespace = (env as unknown as { WORKFLOW_INSTANCE: DurableObjectNamespace }).WORKFLOW_INSTANCE;
  const id = namespace.idFromName("tenant:norm-test:placement:promotion");
  const stub = namespace.get(id);
  const configure = (deployment: Partial<Deployment>) => runInDurableObject(stub, async object => {
    (object as unknown as FixtureHost).configureNormTestPlanning(deployment);
  });
  await runInDurableObject(stub, async object => {
    (object as unknown as FixtureHost).configureNormTestPublicBindings(vector.public_bindings,
      [{ object_id: id.toString(), checkpoint: vector.checkpoint }]);
  });
  const send = (operation: string, body: unknown, authorized = true) => SELF.fetch(
    `https://runtime.test/v1/tenants/norm-test/placements/promotion/host/norm/${operation}`, {
      method: "POST", headers: { "content-type": "application/json", ...(authorized ? { authorization: "Bearer control-token" } : {}) },
      body: JSON.stringify(body),
    });
  const promotion = (name: string) => ({
    protocol: "whipplescript.norm.promotion/v1", command: { stream: vector.stream, promotion: name, tokens: [] },
  });
  const promote = async (name: string) => {
    const response = await send("promotions", promotion(name));
    const body = await response.json() as Answer;
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(body.protocol).toBe("whipplescript.norm.promotion/v1");
    return body.result;
  };
  const refusedWith = async (name: string, status: number, message: string) => {
    const response = await send("promotions", promotion(name));
    expect(response.status).toBe(status);
    expect(await response.json()).toEqual({ error: expect.stringContaining(message) });
  };
  const seed = (tables: Table[]) => runInDurableObject(stub, async (_object, state) => {
    for (const table of tables) {
      expect(/^[a-z_][a-z0-9_]*$/.test(table.table)).toBe(true);
      for (const column of table.columns) expect(/^[a-z_][a-z0-9_]*$/.test(column)).toBe(true);
      // A table the Worker's object has not created yet is created exactly
      // as the native door's own lazy DDL created it.
      const present = state.storage.sql.exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table.table).toArray();
      if (present.length === 0) for (const ddl of table.ddl) state.storage.sql.exec(ddl);
      for (const row of table.rows) state.storage.sql.exec(
        `INSERT INTO "${table.table}" (${table.columns.map(column => `"${column}"`).join(",")}) VALUES (${row.map(() => "?").join(",")})`, ...row);
    }
  });
  // The mainline as the object holds it: its head, and the subject's bytes
  // read through the head's manifest.
  const mainline = () => runInDurableObject(stub, async (_object, state) => {
    const [branch] = state.storage.sql.exec<{ head_cut_id: string; head_manifest_hash: string }>(
      "SELECT head_cut_id, head_manifest_hash FROM branches WHERE branch_id = 'main'").toArray();
    const blob = (id: string) => state.storage.sql.exec<{ body: string }>("SELECT body FROM content_blobs WHERE id = ?", id).toArray()[0]?.body;
    // A workspace this small is one leaf of the manifest tree.
    const manifest = JSON.parse(blob(branch.head_manifest_hash)) as { tag: string; level: number; entries: Array<[string, string]> };
    expect(manifest).toMatchObject({ tag: "whipplescript.manifest-tree.v2", level: 0 });
    const entry = manifest.entries.find(([path]) => path === vector.path);
    return { head: branch.head_cut_id, subject: entry && blob(entry[1]) };
  });

  // Nothing installed: the route refuses before it reads the object.
  const unauthorized = await send("promotions", promotion("unauthorized"), false);
  expect(unauthorized.status).toBe(401); await unauthorized.body?.cancel();
  await refusedWith("uninstalled", 503, "norm planning installation is unavailable");

  // The governed object: Main at the demo's A0, W's line `work` holding the
  // repaired parser, and C0 with R0 accepted, imported through the door that
  // leases the mainline to its gate.
  await seed(vector.workspace);
  const provision = await send("provision", {});
  expect(provision.status).toBe(200); await provision.body?.cancel();
  const imported = await send("commands", { protocol: "whipplescript.norm.commands/v1", command: { kind: "import", events: vector.events } });
  expect(imported.status, await imported.clone().text()).toBe(200); await imported.body?.cancel();
  const base = await mainline();
  expect(base.subject).toBe(vector.base);
  await refusedWith("uninstalled", 503, "norm planning installation is unavailable");
  expect(await mainline()).toEqual(base);

  // R0 has no support at the candidate: refused naming it, Main unmoved.
  await configure(vector.deployment);
  const refused = await promote("unsupported");
  expect(refused).toEqual(vector.refused);
  expect(refused.detail!.requirements[vector.requirement]).toEqual(["check"]);
  expect(refused.reason).toBe(`the proposed result is not supported: ${vector.requirement} (check)`);
  expect(await mainline()).toEqual(base);

  // Q0's passing run at the candidate, settled in the object's journal and
  // published on the ledger.
  await seed(vector.journal);
  const observed = await send("commands", { protocol: "whipplescript.norm.commands/v1", command: { kind: "import", events: vector.supported_events } });
  const observedBody = await observed.json() as { result: { inserted: number } };
  expect(observed.status, JSON.stringify(observedBody)).toBe(200);
  expect(observedBody.result.inserted).toBe(vector.supported_events.length - vector.events.length);

  // A deployment whose image is not the one its runtime binding names cannot
  // evaluate the gate at all, and each missing premise is no installation.
  await configure({ ...vector.deployment, deployed_image: `sha256:${"d".repeat(64)}` });
  await refusedWith("misconfigured", 400, "runtime image binding differs from deployment image or selected runtime");
  expect(await mainline()).toEqual(base);
  for (const field of ["planning", "runtime", "image_binding", "deployed_image"] as const) {
    const missing: Partial<Deployment> = { ...vector.deployment }; delete missing[field];
    await configure(missing);
    await refusedWith(`without-${field}`, 503, "norm planning installation is unavailable");
    expect(await mainline()).toEqual(base);
  }

  // Supported: admitted, and the candidate is the mainline.
  await configure(vector.deployment);
  const admitted = await promote("supported");
  expect(admitted).toEqual(vector.admitted);
  expect(admitted.promoted).toBe(vector.stream);
  const promoted = await mainline();
  expect(promoted.head).not.toBe(base.head);
  expect(promoted.subject).toBe(vector.candidate);
});
