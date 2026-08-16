import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  isDelegated,
  missingEnvironment,
  partition,
  runProductionWiringCanaries,
} from "./run-production-wiring-canaries.mjs";

function childThatCloses(code) {
  const child = new EventEmitter();
  queueMicrotask(() => child.emit("close", code, null));
  return child;
}

const canaries = {
  suites: [
    {
      id: "local-one",
      state: "ready-awaiting-identity",
      runner: "scripts/production-wiring-canary.mjs#local-one",
      requiredEnvironment: ["GW_SYNTHETIC_WHIP_TENANT"],
      surfaces: ["whip-runtime"],
    },
    {
      id: "delegated-one",
      state: "ready-awaiting-identity",
      runner: "gaugewright-cloud@1672ef5a:scripts/production-wiring-canary.mjs#panels-audience-lifecycle",
      requiredEnvironment: ["GW_SYNTHETIC_PANELS_AUTHORITY"],
      surfaces: ["whip-runtime"],
    },
  ],
};

test("a runner in another repository is told apart from a local one", () => {
  assert.equal(isDelegated("gaugewright-cloud@1672ef5a:scripts/x.mjs#y"), true);
  assert.equal(isDelegated("scripts/x.mjs#y"), false);
  // A path that merely contains an at-sign is not a cross-repository reference.
  assert.equal(isDelegated("scripts/@scope/x.mjs#y"), false);
});

test("a delegated suite is neither run nor counted against this lane", async () => {
  const { local, delegated } = partition(canaries.suites);
  assert.deepEqual(local.map((s) => s.id), ["local-one"]);
  assert.deepEqual(delegated.map((s) => s.id), ["delegated-one"]);

  // Its credentials are not this lane's to hold, so they are not demanded here.
  assert.deepEqual(missingEnvironment(local, {}), ["GW_SYNTHETIC_WHIP_TENANT"]);
});

test("asking for a delegated suite says where its journey is, not \"unknown\"", async () => {
  await assert.rejects(
    runProductionWiringCanaries({
      canaries,
      root: "/repo",
      environment: {},
      spawnImpl: () => childThatCloses(0),
      selection: "delegated-one",
    }),
    /is not run here: its journey is gaugewright-cloud@1672ef5a/,
  );
});

test("a run reports the delegated suite rather than dropping it", async () => {
  const result = await runProductionWiringCanaries({
    canaries,
    root: "/repo",
    environment: { GW_SYNTHETIC_WHIP_TENANT: "x" },
    spawnImpl: () => childThatCloses(0),
  });
  assert.deepEqual(result.executed, ["local-one"]);
  assert.deepEqual(result.delegated.map((s) => s.id), ["delegated-one"]);
});

test("a deploy selects by surface, and only local suites answer", async () => {
  const result = await runProductionWiringCanaries({
    canaries,
    root: "/repo",
    environment: { GW_SYNTHETIC_WHIP_TENANT: "x" },
    spawnImpl: () => childThatCloses(0),
    selection: "surface:whip-runtime",
  });
  assert.deepEqual(result.executed, ["local-one"]);
});
