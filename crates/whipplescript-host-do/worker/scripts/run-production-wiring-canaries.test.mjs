import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { runners } from "./production-wiring-canary.mjs";
import {
  dispatchPlan,
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

test("a suite is started by its runner's marker, and a shared journey runs once", async () => {
  const shared = {
    suites: [
      {
        id: "journey-owner",
        state: "ready-awaiting-identity",
        runner: "scripts/production-wiring-canary.mjs#journey",
        requiredEnvironment: ["GW_SYNTHETIC_WHIP_TENANT"],
      },
      {
        id: "journey-rider",
        state: "ready-awaiting-identity",
        runner: "scripts/production-wiring-canary.mjs#journey",
        requiredEnvironment: ["GW_SYNTHETIC_WHIP_TENANT"],
      },
    ],
  };
  const spawned = [];
  const result = await runProductionWiringCanaries({
    canaries: shared,
    root: "/repo",
    environment: { GW_SYNTHETIC_WHIP_TENANT: "x" },
    spawnImpl: (command, args) => {
      spawned.push(args);
      return childThatCloses(0);
    },
  });
  assert.deepEqual(spawned, [["/repo/scripts/production-wiring-canary.mjs", "journey"]]);
  assert.deepEqual(result.executed, ["journey-owner", "journey-rider"]);
});

test("a failed shared journey fails every suite it proves", async () => {
  await assert.rejects(
    runProductionWiringCanaries({
      canaries: {
        suites: [
          { id: "a", state: "ready-awaiting-identity", runner: "scripts/x.mjs#j" },
          { id: "b", state: "ready-awaiting-identity", runner: "scripts/x.mjs#j" },
        ],
      },
      root: "/repo",
      environment: {},
      spawnImpl: () => childThatCloses(1),
    }),
    /production wiring canaries failed: a and b via #j \(exit 1\)/,
  );
});

test("a runner without a marker is refused before anything is spawned", async () => {
  await assert.rejects(
    runProductionWiringCanaries({
      canaries: {
        suites: [{ id: "a", state: "ready-awaiting-identity", runner: "scripts/x.mjs" }],
      },
      root: "/repo",
      environment: {},
      spawnImpl: () => assert.fail("spawned a runner with no marker"),
    }),
    /suite a has no runner marker/,
  );
});

test("every ready local suite in the inventory starts a journey the runner has", async () => {
  const inventory = JSON.parse(await readFile(
    resolve(import.meta.dirname, "../contracts/production-canaries.json"),
    "utf8",
  ));
  const plan = dispatchPlan(partition(inventory.suites).local);
  for (const step of plan) {
    assert.equal(step.locator, "scripts/production-wiring-canary.mjs");
    assert(
      Object.hasOwn(runners, step.marker),
      `${step.suites.join(", ")} would start the runner with #${step.marker}, which it does not dispatch`,
    );
  }
  // The whole inventory, as a full lane run would start it.
  const spawned = [];
  const environment = Object.fromEntries(
    partition(inventory.suites).local
      .flatMap((suite) => suite.requiredEnvironment)
      .map((name) => [name, "synthetic"]),
  );
  const result = await runProductionWiringCanaries({
    canaries: inventory,
    root: "/repo",
    environment,
    spawnImpl: (command, args) => {
      spawned.push(args[1]);
      return childThatCloses(0);
    },
  });
  assert.deepEqual(spawned, ["managed-host-lifecycle", "private-home-forwarding"]);
  assert(result.executed.includes("placement-forwarding"));
});
