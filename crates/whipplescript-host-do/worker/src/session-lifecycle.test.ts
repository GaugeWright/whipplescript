import assert from "node:assert/strict";
import { test } from "node:test";

import {
  deadlineAt,
  decide,
  evolve,
  fold,
  initialLifecycleState,
  isRejection,
  type LifecycleCommand,
  type LifecycleEvent,
  type LifecycleState,
} from "./session-lifecycle.ts";

/** Apply a command through decide/evolve, asserting it was admitted. */
function apply(
  state: LifecycleState,
  command: LifecycleCommand,
): { state: LifecycleState; events: LifecycleEvent[] } {
  const outcome = decide(state, command);
  assert.ok(!isRejection(outcome), `expected admission, got ${JSON.stringify(outcome)}`);
  return { state: outcome.reduce(evolve, state), events: outcome };
}

const OPEN: LifecycleCommand = { kind: "open", atMs: 1_000, collectionDeclared: false };
const OPEN_COLLECTING: LifecycleCommand = {
  kind: "open",
  atMs: 1_000,
  collectionDeclared: true,
};
const IDLE = 60_000;
const ABSOLUTE = 600_000;

function live(command: LifecycleCommand = OPEN): LifecycleState {
  const opened = apply(initialLifecycleState, command);
  return apply(opened.state, { kind: "activate" }).state;
}

test("phase is the fold of admitted events, not a stored field", () => {
  const events: LifecycleEvent[] = [
    { type: "opened", atMs: 1_000, collectionDeclared: false },
    { type: "activated" },
    { type: "activityObserved", atMs: 5_000 },
    { type: "deadlineReached", atMs: 90_000 },
  ];
  const folded = fold(events);
  assert.equal(folded.phase, "expiring");
  assert.equal(folded.lastActivityMs, 5_000);
  // Replaying the same events reaches the same state.
  assert.deepEqual(fold(events), folded);
});

test("a deadline observation before the lease is a no-op, not a rejection", () => {
  const state = live();
  const outcome = decide(state, {
    kind: "observeDeadline",
    atMs: 30_000,
    idleTtlMs: IDLE,
    absoluteTtlMs: ABSOLUTE,
  });
  assert.ok(!isRejection(outcome));
  assert.deepEqual(outcome, []);
});

test("the idle bound expires from the last observed activity", () => {
  let state = live();
  state = apply(state, { kind: "observeActivity", atMs: 50_000 }).state;
  assert.equal(deadlineAt(state, IDLE, ABSOLUTE), 110_000);

  const early = decide(state, {
    kind: "observeDeadline",
    atMs: 109_999,
    idleTtlMs: IDLE,
    absoluteTtlMs: ABSOLUTE,
  });
  assert.deepEqual(early, []);

  const due = apply(state, {
    kind: "observeDeadline",
    atMs: 110_000,
    idleTtlMs: IDLE,
    absoluteTtlMs: ABSOLUTE,
  });
  assert.equal(due.state.phase, "expiring");
});

test("the absolute bound caps a continuously active session", () => {
  let state = live();
  state = apply(state, { kind: "observeActivity", atMs: 600_500 }).state;
  // Idle would allow 660_500; the absolute bound from open wins.
  assert.equal(deadlineAt(state, IDLE, ABSOLUTE), 601_000);
});

test("activity in the grace window returns an expiring session to active", () => {
  let state = live();
  state = apply(state, {
    kind: "observeDeadline",
    atMs: 61_000,
    idleTtlMs: IDLE,
    absoluteTtlMs: ABSOLUTE,
  }).state;
  assert.equal(state.phase, "expiring");
  state = apply(state, { kind: "observeActivity", atMs: 61_500 }).state;
  assert.equal(state.phase, "active");
});

test("no reducer path reads a clock: identical commands fold identically", () => {
  const first = fold([
    { type: "opened", atMs: 1_000, collectionDeclared: true },
    { type: "activated" },
  ]);
  const second = fold([
    { type: "opened", atMs: 1_000, collectionDeclared: true },
    { type: "activated" },
  ]);
  assert.deepEqual(first, second);
});

test("teardown is refused while a declared collection is pending", () => {
  const state = live(OPEN_COLLECTING);
  assert.equal(state.collection, "pending");
  const outcome = decide(state, { kind: "tearDown" });
  assert.ok(isRejection(outcome));
  assert.match(outcome.rejected, /collection has not settled/);
});

test("teardown proceeds once a collection settles", () => {
  let state = live(OPEN_COLLECTING);
  state = apply(state, { kind: "settleCollection" }).state;
  const torn = apply(state, { kind: "tearDown" }).state;
  assert.equal(torn.phase, "tornDown");
});

test("teardown proceeds once a collection terminally fails", () => {
  let state = live(OPEN_COLLECTING);
  state = apply(state, { kind: "failCollection" }).state;
  const torn = apply(state, { kind: "tearDown" }).state;
  assert.equal(torn.phase, "tornDown");
});

test("a session with no declared collection tears down directly", () => {
  const torn = apply(live(), { kind: "tearDown" }).state;
  assert.equal(torn.phase, "tornDown");
});

test("teardown retains the transcript and the session fact in every shape", () => {
  for (const command of [OPEN, OPEN_COLLECTING]) {
    let state = live(command);
    if (state.collection === "pending") {
      state = apply(state, { kind: "settleCollection" }).state;
    }
    const torn = apply(state, { kind: "tearDown" }).state;
    assert.equal(torn.transcriptRetained, true);
    assert.equal(torn.sessionOccurred, true);
  }
});

test("the session fact is recorded only at teardown", () => {
  let state = live();
  assert.equal(state.sessionOccurred, false);
  state = apply(state, {
    kind: "observeDeadline",
    atMs: 61_000,
    idleTtlMs: IDLE,
    absoluteTtlMs: ABSOLUTE,
  }).state;
  assert.equal(state.sessionOccurred, false);
  assert.equal(apply(state, { kind: "tearDown" }).state.sessionOccurred, true);
});

test("terminal is absorbing", () => {
  const torn = apply(live(), { kind: "tearDown" }).state;
  for (const command of [
    { kind: "activate" },
    { kind: "observeActivity", atMs: 99_000 },
    { kind: "observeDeadline", atMs: 99_000, idleTtlMs: IDLE, absoluteTtlMs: ABSOLUTE },
    { kind: "tearDown" },
  ] satisfies LifecycleCommand[]) {
    assert.ok(isRejection(decide(torn, command)), `${command.kind} must be refused`);
  }
});

test("a session opens exactly once", () => {
  const opened = apply(initialLifecycleState, OPEN).state;
  assert.ok(isRejection(decide(opened, OPEN)));
});

test("settling a collection that was never declared is refused", () => {
  const state = live();
  assert.ok(isRejection(decide(state, { kind: "settleCollection" })));
  assert.ok(isRejection(decide(state, { kind: "failCollection" })));
});

test("collection settlement is not repeatable", () => {
  let state = live(OPEN_COLLECTING);
  state = apply(state, { kind: "settleCollection" }).state;
  assert.ok(isRejection(decide(state, { kind: "settleCollection" })));
});

test("the runtime state carries no principal mode or conversation outcome", () => {
  const torn = apply(live(), { kind: "tearDown" }).state;
  const keys = Object.keys(torn).join(",");
  for (const absent of ["authenticated", "durableChat", "audience", "deployment"]) {
    assert.ok(!keys.includes(absent), `runtime state must not carry ${absent}`);
  }
});
