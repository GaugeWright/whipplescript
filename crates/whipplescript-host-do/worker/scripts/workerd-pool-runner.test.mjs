import assert from "node:assert/strict";
import { test } from "node:test";
import { getEventListeners } from "node:events";
import { execFileSync } from "node:child_process";
import { runPool } from "./workerd-pool-runner.mjs";

const hanging = `process.on('SIGTERM', () => {}); console.log('ready'); setInterval(() => {}, 1000);`;
function assertGone(pid) {
  assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
}

async function assertStopped(descendant) {
  let stopped = false;
  for (let attempt = 0; attempt < 10 && !stopped; ++attempt) {
    try {
      process.kill(descendant, 0);
      // A dead orphan may briefly await reaping; it cannot execute anymore.
      const state = execFileSync("ps", ["-o", "stat=", "-p", String(descendant)], { encoding: "utf8", timeout: 1000 }).trim();
      stopped = state.startsWith("Z");
    } catch (error) {
      if (error.code === "ESRCH" || error.status === 1) stopped = true;
      else throw error;
    }
    if (!stopped) await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.ok(stopped, "the descendant must not remain running after its parent closes");
}

test("abort terminates a hung fixture despite ignored SIGTERM", { timeout: 5000 }, async (context) => {
  const controller = new AbortController();
  let pid;
  let samples = 0;
  const failure = new Error("fixture deadline");
  await assert.rejects(runPool({
    command: process.execPath, args: ["-e", hanging], signal: controller.signal,
    onStart: value => { pid = value; },
    onOutput: () => controller.abort(failure),
    sample: () => { ++samples; }, killAfterMs: 50,
  }), error => error === failure);
  assertGone(pid);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  const finishedSamples = samples;
  await new Promise(resolve => setTimeout(resolve, 150));
  assert.equal(samples, finishedSamples, "sampler must be cleared after abort");
  assert.equal(context.signal.aborted, false);
});

test("sampler errors terminate the fixture and reject instead of escaping an interval", { timeout: 5000 }, async () => {
  let pid;
  let samples = 0;
  const failure = new Error("sampling unavailable");
  await assert.rejects(runPool({
    command: process.execPath, args: ["-e", hanging],
    onStart: value => { pid = value; },
    sample: () => { ++samples; throw failure; }, killAfterMs: 50,
  }), error => error === failure);
  assertGone(pid);
  const finishedSamples = samples;
  await new Promise(resolve => setTimeout(resolve, 150));
  assert.equal(samples, finishedSamples, "failed sampler must not keep running");
});


test("an early parent exit does not leave its ignored-SIGTERM descendant alive", { timeout: 5000, skip: process.platform === "win32" }, async () => {
  const controller = new AbortController();
  let pid;
  let descendant;
  const parent = `const { spawn } = require('node:child_process');
const child = spawn(process.execPath, ['-e', "process.on('SIGTERM', () => {}); console.log('ready'); setInterval(() => {}, 1000);"], { stdio: ['ignore', 'pipe', 'ignore'] });
child.stdout.once('data', () => console.log('ready:' + child.pid));
setInterval(() => {}, 1000);`;
  const failure = new Error("fixture aborted");
  await assert.rejects(runPool({
    command: process.execPath, args: ["-e", parent], signal: controller.signal,
    onStart: value => { pid = value; },
    onOutput: chunk => {
      const match = String(chunk).match(/ready:(\d+)/);
      if (match) { descendant = Number(match[1]); controller.abort(failure); }
    }, killAfterMs: 50,
  }), error => error === failure);
  assertGone(pid);
  assert.ok(descendant, "the descendant must start before abort");
  await assertStopped(descendant);
});


test("successful parent completion also stops its closed-pipe descendant", { timeout: 5000, skip: process.platform === "win32" }, async () => {
  let pid;
  let descendant;
  const parent = `const { spawn } = require('node:child_process');
const child = spawn(process.execPath, ['-e', "process.on('SIGTERM', () => {}); console.log('ready'); setInterval(() => {}, 1000);"], { stdio: ['ignore', 'pipe', 'ignore'] });
child.stdout.once('data', () => { console.log('ready:' + child.pid); process.exit(0); });`;
  const result = await runPool({
    command: process.execPath, args: ["-e", parent],
    onStart: value => { pid = value; },
    onOutput: chunk => {
      const match = String(chunk).match(/ready:(\d+)/);
      if (match) descendant = Number(match[1]);
    },
  });
  assert.equal(result.code, 0, "cleanup must preserve a successful parent verdict");
  assertGone(pid);
  assert.ok(descendant, "the descendant must start before success");
  await assertStopped(descendant);
});
