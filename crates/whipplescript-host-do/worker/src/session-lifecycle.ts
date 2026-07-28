// The session runtime jurisdiction's lifecycle (DR-0049 §2, §3, §5).
//
// Pure `decide`/`evolve`. Phase is the fold of admitted events; it is never
// stored as an implied property of a mutable record, and nothing here reads a
// clock — the imperative shell stamps every time at the host boundary and
// passes it in, exactly as the coordination resources already require.
//
// This half owns instance lifetime, lease enforcement, and terminal artifact
// settlement. Whether an unbound principal is "anonymous", whether a durable
// conversation persists, and who funds the session are the embedder's governed
// facts and deliberately absent here.

export type Phase = "init" | "opened" | "active" | "expiring" | "tornDown";

/** `none` when the release declares no collection; otherwise it must reach a
 * terminal disposition before the session may tear down. */
export type CollectionStatus = "none" | "pending" | "settled" | "failed";

export interface LifecycleState {
  phase: Phase;
  openedAtMs: number;
  lastActivityMs: number;
  collection: CollectionStatus;
  /** Set at teardown in every principal shape (TERMINAL_RETAINS_TRANSCRIPT). */
  transcriptRetained: boolean;
  /** The one session-occurred fact, recorded only at teardown. */
  sessionOccurred: boolean;
}

export type LifecycleCommand =
  | { kind: "open"; atMs: number; collectionDeclared: boolean }
  | { kind: "activate" }
  | { kind: "observeActivity"; atMs: number }
  | {
      kind: "observeDeadline";
      atMs: number;
      idleTtlMs: number;
      absoluteTtlMs: number;
    }
  | { kind: "settleCollection" }
  | { kind: "failCollection" }
  | { kind: "tearDown" };

export type LifecycleEvent =
  | { type: "opened"; atMs: number; collectionDeclared: boolean }
  | { type: "activated" }
  | { type: "activityObserved"; atMs: number }
  | { type: "deadlineReached"; atMs: number }
  | { type: "collectionSettled" }
  | { type: "collectionFailed" }
  | { type: "tornDown" };

export interface Rejection {
  rejected: string;
}

export const initialLifecycleState: LifecycleState = {
  phase: "init",
  openedAtMs: 0,
  lastActivityMs: 0,
  collection: "none",
  transcriptRetained: false,
  sessionOccurred: false,
};

function reject(reason: string): Rejection {
  return { rejected: reason };
}

/**
 * The lease deadline, computed from folded state and the embedder's bounds.
 * Exported so the shell can schedule an alarm; the shell must still present the
 * firing time back as an `observeDeadline` command rather than acting on it.
 */
export function deadlineAt(
  state: LifecycleState,
  idleTtlMs: number,
  absoluteTtlMs: number,
): number {
  return Math.min(
    state.openedAtMs + absoluteTtlMs,
    state.lastActivityMs + idleTtlMs,
  );
}

export function decide(
  state: LifecycleState,
  command: LifecycleCommand,
): LifecycleEvent[] | Rejection {
  switch (command.kind) {
    case "open":
      if (state.phase !== "init") return reject("open: session already opened");
      return [
        {
          type: "opened",
          atMs: command.atMs,
          collectionDeclared: command.collectionDeclared,
        },
      ];

    case "activate":
      if (state.phase !== "opened") return reject("activate: only from opened");
      return [{ type: "activated" }];

    case "observeActivity":
      if (state.phase !== "active" && state.phase !== "expiring") {
        return reject("observeActivity: only from active or expiring");
      }
      return [{ type: "activityObserved", atMs: command.atMs }];

    // Time enters here and nowhere else. A firing before the deadline is an
    // ordinary no-op observation, not a rejection: the shell reschedules.
    case "observeDeadline": {
      if (state.phase !== "active" && state.phase !== "expiring") {
        return reject("observeDeadline: only from active or expiring");
      }
      if (state.phase === "expiring") return [];
      const due = deadlineAt(state, command.idleTtlMs, command.absoluteTtlMs);
      return command.atMs >= due ? [{ type: "deadlineReached", atMs: command.atMs }] : [];
    }

    case "settleCollection":
      if (state.collection !== "pending") {
        return reject("settleCollection: no pending collection");
      }
      return [{ type: "collectionSettled" }];

    case "failCollection":
      if (state.collection !== "pending") {
        return reject("failCollection: no pending collection");
      }
      return [{ type: "collectionFailed" }];

    // TERMINAL_REQUIRES_COLLECTION_SETTLED. A session whose declared collection
    // has not reached a terminal disposition cannot tear down, so the path that
    // failed to deliver an artifact can never be the path that erases it.
    case "tearDown":
      if (state.phase === "init" || state.phase === "tornDown") {
        return reject("tearDown: only from a live session");
      }
      if (state.collection === "pending") {
        return reject("tearDown: collection has not settled");
      }
      return [{ type: "tornDown" }];
  }
}

export function evolve(
  state: LifecycleState,
  event: LifecycleEvent,
): LifecycleState {
  switch (event.type) {
    case "opened":
      return {
        ...state,
        phase: "opened",
        openedAtMs: event.atMs,
        lastActivityMs: event.atMs,
        collection: event.collectionDeclared ? "pending" : "none",
      };
    case "activated":
      return { ...state, phase: "active" };
    case "activityObserved":
      return {
        ...state,
        phase: "active",
        lastActivityMs: Math.max(state.lastActivityMs, event.atMs),
      };
    case "deadlineReached":
      return { ...state, phase: "expiring" };
    case "collectionSettled":
      return { ...state, collection: "settled" };
    case "collectionFailed":
      return { ...state, collection: "failed" };
    case "tornDown":
      // The append-only floor: the transcript handle and the one session fact
      // survive teardown in every principal shape. Payload resolution is
      // removed by the erasure path, which never rewrites these events.
      return {
        ...state,
        phase: "tornDown",
        transcriptRetained: true,
        sessionOccurred: true,
      };
  }
}

export function fold(events: LifecycleEvent[]): LifecycleState {
  return events.reduce(evolve, initialLifecycleState);
}

export function isRejection(
  outcome: LifecycleEvent[] | Rejection,
): outcome is Rejection {
  return !Array.isArray(outcome);
}
