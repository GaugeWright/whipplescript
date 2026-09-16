// Storage and transport only: the Rust reducer owns invocation validation and
// lifecycle decisions. This route is reachable only over the private broker
// binding; selected identity comes from the workflow host, not a public caller.
export interface ReceiptReducer {
  prepareFence(selected: string, envelope: string, receipt: string | undefined, placement: string | undefined, container: string, dispatch: string, operation: string): string;
  resolve(selected: string, envelope: string, receipt: string, placement: string, stored: string | undefined, operation: string): string;
  claim(selected: string, envelope: string, stored?: string): string;
  place(selected: string, envelope: string, receipt: string, stored: string | undefined, container: string, dispatch: string): string;
  target(selected: string, envelope: string, receipt: string, placement: string): string;
  result(placement: string, response: string): string;
  complete(selected: string, envelope: string, stored: string, status: number, body: string): string;
}

type Claim = {
  storage_key: string;
  dispatch: unknown;
  decision:
    | { action: "dispatch"; receipt: unknown }
    | { action: "pending" }
    | { action: "replay"; status: number; body: unknown };
};

export class ExecutorReceipts {
  constructor(privateStorage: DurableObjectStorage, reducer: ReceiptReducer) {
    this.storage = privateStorage;
    this.reducer = reducer;
    this.storage.sql.exec("CREATE TABLE IF NOT EXISTS exec_provider_receipts_v1 (invocation TEXT PRIMARY KEY, receipt_json TEXT NOT NULL)");
    this.storage.sql.exec("CREATE TABLE IF NOT EXISTS exec_provider_placements_v1 (invocation TEXT PRIMARY KEY REFERENCES exec_provider_receipts_v1(invocation), placement_json TEXT NOT NULL)");
    this.storage.sql.exec("CREATE TABLE IF NOT EXISTS exec_provider_resolutions_v1 (invocation TEXT PRIMARY KEY REFERENCES exec_provider_receipts_v1(invocation), resolution_json TEXT NOT NULL)");
  }

  private readonly storage: DurableObjectStorage;
  private readonly reducer: ReceiptReducer;

  private read(key: string): string | undefined {
    const rows = this.storage.sql.exec<{ receipt_json: string }>(
      "SELECT receipt_json FROM exec_provider_receipts_v1 WHERE invocation = ?", key,
    ).toArray();
    return rows[0]?.receipt_json;
  }

  // Fence-only custody can precede placement; no reconciliation enters execution.
  async reconcile(request: Request, query: (container: string, placement: unknown, operation: { op: "read" | "fence"; fence_id?: string }, headers: Headers) => Promise<Response>, fenceContainer: string): Promise<Response> {
    if (request.method !== "POST") return Response.json({ error: "POST required" }, { status: 405 });
    const command = await request.json() as { selected: unknown; envelope: unknown; operation: { op?: unknown; fence_id?: unknown } };
    // Observe accepts only the response from our private controller binding.
    // It is never admitted from even an internal caller's request body.
    if (!command.operation || !["read", "fence", "ensure_fence"].includes(command.operation.op as string)) {
      return Response.json({ error: "read, fence or ensure_fence operation required" }, { status: 400 });
    }
    const selected = JSON.stringify(command.selected);
    const envelope = JSON.stringify(command.envelope);
    const inspected = JSON.parse(this.reducer.claim(selected, envelope)) as Claim;
    const key = inspected.storage_key;
    type Resolution = { record: unknown; receipt: unknown; query: { op: "read" | "fence"; fence_id?: string } | null;
      view: { placement: { container_id: string }; [key: string]: unknown } };
    const reduce = (operation: unknown): Resolution => this.storage.transactionSync(() => {
      let receipt = this.read(key);
      let placement = this.storage.sql.exec<{ placement_json: string }>(
        "SELECT placement_json FROM exec_provider_placements_v1 WHERE invocation = ?", key,
      ).toArray()[0]?.placement_json;
      if (receipt === undefined || placement === undefined) {
        const prepared = JSON.parse(this.reducer.prepareFence(selected, envelope, receipt, placement, fenceContainer, crypto.randomUUID(), JSON.stringify(operation))) as {receipt: unknown; placement: unknown};
        if (receipt === undefined) {
          receipt = JSON.stringify(prepared.receipt);
          const inserted = this.storage.sql.exec("INSERT INTO exec_provider_receipts_v1 (invocation, receipt_json) VALUES (?, ?) RETURNING invocation", key, receipt).toArray();
          if (inserted.length !== 1) throw new Error("executor fence custody did not retain its receipt");
        }
        if (placement === undefined) {
          placement = JSON.stringify(prepared.placement);
          const inserted = this.storage.sql.exec("INSERT INTO exec_provider_placements_v1 (invocation, placement_json) VALUES (?, ?) RETURNING invocation", key, placement).toArray();
          if (inserted.length !== 1) throw new Error("executor fence custody did not retain its placement");
        }
      }
      const stored = this.storage.sql.exec<{ resolution_json: string }>(
        "SELECT resolution_json FROM exec_provider_resolutions_v1 WHERE invocation = ?", key,
      ).toArray()[0]?.resolution_json;
      const result = JSON.parse(this.reducer.resolve(selected, envelope, receipt, placement, stored, JSON.stringify(operation))) as Resolution;
      const resolutionWrite = this.storage.sql.exec(
        "INSERT INTO exec_provider_resolutions_v1 (invocation, resolution_json) VALUES (?, ?) ON CONFLICT(invocation) DO UPDATE SET resolution_json = excluded.resolution_json RETURNING invocation",
        key, JSON.stringify(result.record),
      ).toArray();
      if (resolutionWrite.length !== 1) throw new Error("executor lifetime retention did not commit its record");
      const receiptWrite = this.storage.sql.exec("UPDATE exec_provider_receipts_v1 SET receipt_json = ? WHERE invocation = ? RETURNING invocation", JSON.stringify(result.receipt), key).toArray();
      if (receiptWrite.length !== 1) throw new Error("executor lifetime retention lost its receipt");
      return result;
    });
    let result = reduce(command.operation);
    if (result.query !== null) {
      const response = await query(result.view.placement.container_id, result.view.placement, result.query, request.headers);
      const body = await response.text();
      if (response.status !== 200) throw new Error("controller reconciliation failed");
      result = reduce({ op: "observe", response: JSON.parse(body) });
    }
    return Response.json(result.view);
  }

  async execute(request: Request, forward: (request: Request, place: (container: string) => string) => Promise<Response>, query: (container: string, placement: unknown, headers: Headers) => Promise<Response>): Promise<Response> {
    const command = await request.json() as { selected: unknown; envelope: unknown };
    const selected = JSON.stringify(command.selected);
    const envelope = JSON.stringify(command.envelope);
    // Validate before touching storage. This preliminary decision is not used
    // to dispatch; the transaction reads and decides against current state.
    const inspected = JSON.parse(this.reducer.claim(selected, envelope)) as Claim;
    const key = inspected.storage_key;
    const claim = this.storage.transactionSync(() => {
      const current = this.read(key);
      const result = JSON.parse(this.reducer.claim(selected, envelope, current)) as Claim;
      if (result.decision.action === "dispatch") {
        const inserted = this.storage.sql.exec(
          "INSERT INTO exec_provider_receipts_v1 (invocation, receipt_json) VALUES (?, ?) RETURNING invocation",
          key, JSON.stringify(result.decision.receipt),
        ).toArray();
        if (inserted.length !== 1) throw new Error("executor admission did not retain its receipt");
      }
      return result;
    });
    if (claim.decision.action === "replay") {
      return Response.json(claim.decision.body, { status: claim.decision.status });
    }
    const pending = () => Response.json({ protocol: "whipplescript.exec.reconciliation/v1", state: "pending" }, { status: 202 });
    const retain = (placement: string, response: Response, body: string): Response => {
      if (response.status !== 200) throw new Error("controller request failed");
      const result = JSON.parse(this.reducer.result(placement, body)) as { action: string; status: number; body: unknown };
      if (result.action !== "replay") return pending();
      this.storage.transactionSync(() => {
        const current = this.read(key);
        if (current === undefined) throw new Error("executor claim disappeared before completion");
        const completed = this.reducer.complete(selected, envelope, current, result.status, JSON.stringify(result.body));
        this.storage.sql.exec("UPDATE exec_provider_receipts_v1 SET receipt_json = ? WHERE invocation = ?", completed, key);
      });
      return Response.json(result.body, { status: result.status });
    };
    if (claim.decision.action === "pending") {
      const target = this.storage.transactionSync(() => {
        const current = this.read(key);
        const placement = this.storage.sql.exec<{ placement_json: string }>(
          "SELECT placement_json FROM exec_provider_placements_v1 WHERE invocation = ?", key,
        ).toArray()[0]?.placement_json;
        if (current === undefined || placement === undefined) return undefined;
        return JSON.parse(this.reducer.target(selected, envelope, current, placement)) as { action: string; container_id: string; placement: unknown };
      });
      if (target?.action !== "query") return pending();
      const response = await query(target.container_id, target.placement, request.headers);
      return retain(JSON.stringify(target.placement), response, await response.text());
    }
    const url = new URL(request.url);
    url.pathname = "/exec";
    const dispatchId = crypto.randomUUID();
    let retainedPlacement: string | undefined;
    const response = await forward(new Request(url, {
      method: "POST", headers: request.headers, body: JSON.stringify(claim.dispatch),
    }), (container) => {
      retainedPlacement = this.storage.transactionSync(() => {
        const receipt = this.read(key);
        if (receipt === undefined) throw new Error("executor claim disappeared before placement");
        const existing = this.storage.sql.exec<{ placement_json: string }>(
          "SELECT placement_json FROM exec_provider_placements_v1 WHERE invocation = ?", key,
        ).toArray()[0]?.placement_json;
        const placement = this.reducer.place(selected, envelope, receipt, existing, container, dispatchId);
        if (existing === undefined) {
          const inserted = this.storage.sql.exec("INSERT INTO exec_provider_placements_v1 (invocation, placement_json) VALUES (?, ?) RETURNING invocation", key, placement).toArray();
          if (inserted.length !== 1) throw new Error("executor admission did not retain its placement");
        }
        return placement;
      });
      return retainedPlacement;
    });
    if (retainedPlacement === undefined) throw new Error("executor transport omitted placement");
    return retain(retainedPlacement, response, await response.text());
  }
}
