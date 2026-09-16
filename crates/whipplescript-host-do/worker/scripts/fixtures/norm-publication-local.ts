// Loopback-only physical fixture. Only initial artifacts and grants are seeded;
// all norm commands, stepping, broker delivery and settlement use production code.
import production, { WorkflowInstance as ProductionWorkflowInstance, ExecutorContainer, WorkspaceBroker } from "../../src/index";
export { ExecutorContainer, WorkspaceBroker };
type Vector = { cases: Array<{ public_bindings: unknown[]; checkpoint: unknown; planning: unknown;
  artifacts: { blobs: Array<{id:string;body:string;byte_len:number}>; cuts: Array<{cut_id:string;change_id:string;branch_id:string;manifest_hash:string;recorded_at:string}> } }> };
type RuntimeEnv = ConstructorParameters<typeof ProductionWorkflowInstance>[1];
export class WorkflowInstance extends ProductionWorkflowInstance {
  private readonly fixtureState: DurableObjectState;
  private readonly fixture: Vector["cases"][number];
  constructor(ctx: DurableObjectState, env: RuntimeEnv & { NORM_PHYSICAL_VECTOR: string }) {
    const index = ctx.id.name?.endsWith("-1") ? 1 : 0;
    const fixture = (JSON.parse(env.NORM_PHYSICAL_VECTOR) as Vector).cases[index];
    super(ctx, { ...env, WHIP_NORM_PLANNING: JSON.stringify(fixture.planning), WHIP_NORM_TRUST: JSON.stringify({ bindings: [], public_bindings: fixture.public_bindings,
      creation_grants: [], restorations: [{ object_id: ctx.id.toString(), checkpoint: fixture.checkpoint }] }) });
    this.fixtureState = ctx; this.fixture = fixture;
  }
  override async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    const sql = this.fixtureState.storage.sql;
    if (path.startsWith("/fixture/")) await request.arrayBuffer();
    if (path === "/fixture/seed") {
      // Schema is initialized by production provision before this operation.
      sql.exec("INSERT INTO capability_schemas (capability, description, schema_json) VALUES ('script.observer','fixture','{}')");
      sql.exec("INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES ('observer',NULL,'script.observer','builtin-script','{}')");
      for (const b of this.fixture.artifacts.blobs) sql.exec("INSERT INTO content_blobs (id,body,byte_len) VALUES (?,?,?)", b.id,b.body,b.byte_len);
      for (const c of this.fixture.artifacts.cuts) sql.exec("INSERT INTO cuts (cut_id,change_id,branch_id,manifest_hash,recorded_at) VALUES (?,?,?,?,?)", c.cut_id,c.change_id,c.branch_id,c.manifest_hash,c.recorded_at);
      return Response.json({ seeded: true });
    }
    if (path === "/fixture/inspect") return Response.json({
      instances: sql.exec("SELECT instance_id,status FROM instances").toArray(),
      runs: sql.exec("SELECT * FROM runs").toArray(),
      events: sql.exec("SELECT * FROM events ORDER BY sequence").toArray(),
    });
    if (path === "/fixture/remove-cut") { sql.exec("DELETE FROM cuts WHERE cut_id = 'cut'"); return Response.json({ removed: true }); }
    return super.fetch(request);
  }
}
export default {
  async fetch(request: Request, env: RuntimeEnv, ctx: ExecutionContext) {
    const url = new URL(request.url);
    if (url.pathname === "/fixture/health") {
      await request.arrayBuffer();
      return Response.json({ alive: true });
    }
    if (url.pathname.startsWith("/fixture/")) {
      const id = url.searchParams.get("id");
      if (id !== "norm-0" && id !== "norm-1") return new Response("unknown fixture", {status:404});
      return env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(id)).fetch(request);
    }
    return production.fetch(request, env, ctx);
  },
};
