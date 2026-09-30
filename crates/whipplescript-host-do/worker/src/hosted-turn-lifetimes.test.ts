import assert from "node:assert/strict";
import test from "node:test";
import { HostedTurnLifetimes } from "./hosted-turn-lifetimes.ts";

test("live and overlapping drives stay cooperative until every drive settles", async () => {
  const lifetimes = new HostedTurnLifetimes();
  let finishFirst!: () => void;
  let finishSecond!: () => void;
  const first = lifetimes.drive("instance\0turn", () => new Promise<void>((resolve) => { finishFirst = resolve; }));
  const second = lifetimes.drive("instance\0turn", () => new Promise<void>((resolve) => { finishSecond = resolve; }));
  const recovery = () => { assert.fail("an active drive cannot be recovered as orphaned"); };
  assert.equal(lifetimes.recoverIfIdle("instance\0turn", recovery), false);
  finishFirst(); await first;
  assert.equal(lifetimes.recoverIfIdle("instance\0turn", recovery), false);
  finishSecond(); await second;
  let calls = 0;
  assert.equal(lifetimes.recoverIfIdle("instance\0turn", () => { calls++; return true; }), true);
  assert.equal(calls, 1);
});

test("lost and rejected drives leave no live marker, and another turn stays independent", async () => {
  const lifetimes = new HostedTurnLifetimes();
  await assert.rejects(lifetimes.drive("first", async () => { throw new Error("transport lost"); }));
  assert.equal(lifetimes.recoverIfIdle("first", () => true), true);
  await lifetimes.drive("first", async () => {
    assert.equal(lifetimes.recoverIfIdle("second", () => true), true);
    assert.equal(lifetimes.recoverIfIdle("first", () => { assert.fail("still active"); }), false);
  });
  // A fresh isolate has no bootstrap/in-memory drive but may have durable work.
  assert.equal(new HostedTurnLifetimes().recoverIfIdle("old-turn", () => true), true);
});
