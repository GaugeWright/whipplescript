// The Rust reducer owns validation and lifecycle decisions. This adapter owns
// SQLite transactions and releases external I/O only after durable admission.
export type ControllerAction =
  | { action: "absent" }
  | { action: "blocked"; barrier_id: string }
  | { action: "terminated"; incarnation: string; fence_id: string; barrier_id: string }
  | { action: "execute"; incarnation: string }
  | { action: "pending"; incarnation: string }
  | { action: "fence_required"; incarnation: string; fence_id: string }
  | { action: "not_admitted"; fence_id: string }
  | { action: "replay"; status: number; body: unknown; termination?: { incarnation: string; fence_id: string; barrier_id: string } };

type Transition = { storage_key: string; record: unknown | null; action: ControllerAction };
export type ControllerReducer = (owner: string, placement: string, stored: string | undefined, operation: string, barrier?: string, observedGeneration?: string) => string;

export interface BarrierReducer {
  inspect(owner: string, stored?: string): string;
  begin(owner: string, stored: string | undefined, inventory: string): string;
  finish(owner: string, stored: string, inventory: string, barrierId: string): string;
}
export type ControllerGate = { generation: string; closing: true; barrier_id: string } | { generation: string; closing: false; barrier_id: string | null };
type BarrierChange = { barrier: unknown | null; updates: { storage_key: string; record: unknown }[]; closing: boolean };

export class ExecutorController {
  constructor(
    private readonly storage: DurableObjectStorage,
    // Supplied by the controlling object's identity, never by request JSON.
    private readonly owner: string,
    private readonly reduce: ControllerReducer,
    private readonly barriers: BarrierReducer,
  ) {
    storage.sql.exec("CREATE TABLE IF NOT EXISTS exec_controller_records_v1 (invocation TEXT PRIMARY KEY, record_json TEXT NOT NULL)");
    storage.sql.exec("CREATE TABLE IF NOT EXISTS exec_controller_barrier_v1 (slot INTEGER PRIMARY KEY CHECK (slot = 1), barrier_json TEXT NOT NULL)");
  }

  private transition(placement: string, operation: unknown, persist = true, observedGeneration = "0"): ControllerAction {
    // Validation/key discovery grants no admission and performs no I/O.
    const inspected = JSON.parse(this.reduce(this.owner, placement, undefined, '{"op":"read"}')) as Transition;
    return this.storage.transactionSync(() => {
      const stored = this.storage.sql.exec<{ record_json: string }>(
        "SELECT record_json FROM exec_controller_records_v1 WHERE invocation = ?", inspected.storage_key,
      ).toArray()[0]?.record_json;
      const result = JSON.parse(this.reduce(this.owner, placement, stored, JSON.stringify(operation), this.barrierRecord(), observedGeneration)) as Transition;
      if (persist && result.record !== null) {
        const next = JSON.stringify(result.record);
        if (next !== stored) {
          this.storage.sql.exec(
            "INSERT INTO exec_controller_records_v1 (invocation, record_json) VALUES (?, ?) ON CONFLICT(invocation) DO UPDATE SET record_json = excluded.record_json",
            result.storage_key, next,
          );
        }
      }
      return result.action;
    });
  }

  private barrierRecord(): string | undefined {
    return this.storage.sql.exec<{ barrier_json: string }>("SELECT barrier_json FROM exec_controller_barrier_v1 WHERE slot = 1").toArray()[0]?.barrier_json;
  }

  gate(): ControllerGate {
    return JSON.parse(this.barriers.inspect(this.owner, this.barrierRecord())) as ControllerGate;
  }

  private inventory(): string {
    const rows = this.storage.sql.exec<{ invocation: string; record_json: string }>("SELECT invocation, record_json FROM exec_controller_records_v1 ORDER BY invocation").toArray();
    return JSON.stringify(rows.map(row => {
      const record = JSON.parse(row.record_json) as { placement: unknown };
      const validated = JSON.parse(this.reduce(this.owner, JSON.stringify(record.placement), row.record_json, '{"op":"read"}')) as Transition;
      if (validated.storage_key !== row.invocation) throw new Error("controller inventory storage key changed");
      return record;
    }));
  }

  private applyBarrier(change: BarrierChange): ControllerGate {
    for (const update of change.updates) {
      const changed = this.storage.sql.exec("UPDATE exec_controller_records_v1 SET record_json = ? WHERE invocation = ? RETURNING invocation", JSON.stringify(update.record), update.storage_key).toArray();
      if (changed.length !== 1) throw new Error("controller barrier target disappeared during commit");
    }
    if (change.barrier !== null) {
      this.storage.sql.exec("INSERT INTO exec_controller_barrier_v1 VALUES (1, ?) ON CONFLICT(slot) DO UPDATE SET barrier_json = excluded.barrier_json", JSON.stringify(change.barrier));
    }
    return this.gate();
  }

  beginBarrier(): ControllerGate {
    return this.storage.transactionSync(() => this.applyBarrier(JSON.parse(this.barriers.begin(this.owner, this.barrierRecord(), this.inventory())) as BarrierChange));
  }

  // Only the host's completed physical barrier may call this method.
  finishBarrier(barrierId: string): ControllerGate {
    return this.storage.transactionSync(() => {
      const stored = this.barrierRecord();
      if (stored === undefined) throw new Error("controller barrier disappeared before completion");
      return this.applyBarrier(JSON.parse(this.barriers.finish(this.owner, stored, this.inventory(), barrierId)) as BarrierChange);
    });
  }

  read(placement: string): ControllerAction {
    return this.transition(placement, { op: "read" }, false);
  }

  fence(placement: string, fenceId: string): ControllerAction {
    return this.transition(placement, { op: "fence", fence_id: fenceId });
  }

  ensureFence(placement: string, proposedFenceId: string): ControllerAction {
    return this.transition(placement, { op: "ensure_fence", fence_id: proposedFenceId });
  }

  async execute(
    placement: string,
    incarnation: string,
    run: (dispatch: unknown) => Promise<{ status: number; body: unknown }>,
    observedGeneration = this.gate().generation,
  ): Promise<ControllerAction> {
    const action = this.transition(placement, { op: "admit", incarnation }, true, observedGeneration);
    if (action.action !== "execute") return action;
    // The reducer has validated this exact placement before admission. A lost
    // transport or failed completion write leaves it admitted, never retryable.
    const dispatch = (JSON.parse(placement) as { envelope: { dispatch: unknown } }).envelope.dispatch;
    const completed = await run(dispatch);
    return this.transition(placement, { op: "complete", incarnation: action.incarnation, status: completed.status, body: completed.body });
  }
}
