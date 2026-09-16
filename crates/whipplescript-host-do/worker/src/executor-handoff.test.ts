import assert from "node:assert/strict";
import test from "node:test";
import { performExecutorHandoff } from "./executor-handoff.ts";

test("typed executor handoff uses the supplied private transport and retains the command", async () => {
  const command = { selected: { instance_id: "instance" }, envelope: { dispatch: { effect_id: "effect" } } };
  let calls = 0;
  const result = await performExecutorHandoff({ url: "http://executor/exec", headers: [["authorization", "Bearer fixture"]], body: command }, async (url, init) => {
    calls++;
    assert.equal(url, "http://executor/exec/invocation");
    assert.deepEqual(JSON.parse(String(init.body)), command);
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer fixture");
    return Response.json({ protocol: "whipplescript.exec.reconciliation/v1", state: "pending" }, { status: 202 });
  }, response => response.json());
  assert.equal(calls, 1);
  assert.equal(JSON.parse(result).status, 202);
});

test("typed handoff transport failure never falls back to another executor", async () => {
  let calls = 0;
  await assert.rejects(performExecutorHandoff({ url: "http://executor/exec", headers: [], body: {} }, async () => {
    calls++;
    throw new Error("delivery lost");
  }, response => response.json()), /delivery lost/);
  assert.equal(calls, 1);
});
