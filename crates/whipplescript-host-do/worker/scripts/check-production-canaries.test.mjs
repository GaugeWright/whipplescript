import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { validateProductionCanaries } from "./check-production-canaries.mjs";
import { runners } from "./production-wiring-canary.mjs";

const root = resolve(import.meta.dirname, "..");
const manifest = JSON.parse(await readFile(
  resolve(root, "contracts/product-routes.json"),
  "utf8",
));
const canaries = JSON.parse(await readFile(
  resolve(root, "contracts/production-canaries.json"),
  "utf8",
));
const journeys = Object.keys(runners);

test("every WhippleScript deployed gap has one cleanup-bounded suite", () => {
  assert.deepEqual(
    validateProductionCanaries(manifest, canaries, journeys),
    { gaps: 26, covered: 31, ready: 23, pending: 8, suites: 11 },
  );
});

test("recorded deployed evidence does not unschedule its continuous canary", () => {
  const changed = structuredClone(manifest);
  const firstGap = changed.contracts.find((contract) =>
    contract.risk === "critical" && contract.evidence.deployed.length === 0);
  firstGap.evidence.deployed.push("production:identified-canary-run");
  assert.deepEqual(
    validateProductionCanaries(changed, canaries, journeys),
    { gaps: 25, covered: 31, ready: 23, pending: 8, suites: 11 },
  );
});

test("an unmapped operation fails the aggregate", () => {
  const changed = structuredClone(canaries);
  changed.suites[0].contracts.pop();
  assert.throws(
    () => validateProductionCanaries(manifest, changed, journeys),
    /production canary map is not exhaustive/,
  );
});

test("a mutable or invented external runner cannot claim evidence", () => {
  const changed = structuredClone(canaries);
  changed.suites[0].runner = "gaugewright-cloud@main:scripts/fake.mjs#public-session";
  assert.throws(
    () => validateProductionCanaries(manifest, changed, journeys),
    /unapproved runner/,
  );
});

test("a missing local runner marker cannot claim readiness", () => {
  const changed = structuredClone(canaries);
  changed.suites[2].runner = "scripts/production-wiring-canary.mjs#invented";
  assert.throws(
    () => validateProductionCanaries(manifest, changed, journeys),
    /local runner marker #invented is not a journey the runner dispatches/,
  );
});

test("a marker that only appears in the runner's source cannot claim readiness", () => {
  // `"content-type"` is a quoted string in the runner, so the old source search
  // accepted it; the lane would have started the runner with it and failed.
  const changed = structuredClone(canaries);
  changed.suites[2].runner = "scripts/production-wiring-canary.mjs#content-type";
  assert.throws(
    () => validateProductionCanaries(manifest, changed, journeys),
    /is not a journey the runner dispatches/,
  );
});

test("a suite that shares another suite's journey is dispatchable by its marker", () => {
  const shared = canaries.suites.find((suite) => suite.id === "placement-forwarding");
  assert.equal(shared.runner, "scripts/production-wiring-canary.mjs#managed-host-lifecycle");
  assert.equal(Object.hasOwn(runners, "placement-forwarding"), false);
  assert.equal(Object.hasOwn(runners, "managed-host-lifecycle"), true);
});

test("a contract configures identifiers it requires, never a secret", () => {
  const ready = canaries.suites.find((suite) => suite.id === "norm-ledger");
  const withConfiguration = (configuration) => ({
    ...canaries,
    suites: canaries.suites.map((suite) => (suite === ready ? { ...suite, configuration } : suite)),
  });
  assert.doesNotThrow(() => validateProductionCanaries(
    manifest, withConfiguration({ GW_SYNTHETIC_WHIP_TENANT: "synthetic-wiring" }), journeys));
  assert.throws(
    () => validateProductionCanaries(
      manifest, withConfiguration({ GW_SYNTHETIC_WHIP_CONTROL_TOKEN: "leaked" }), journeys),
    /a secret belongs in the store/,
  );
  assert.throws(
    () => validateProductionCanaries(
      manifest, withConfiguration({ GW_SYNTHETIC_UNREQUIRED: "x" }), journeys),
    /which it does not require/,
  );
  assert.throws(
    () => validateProductionCanaries(
      manifest, withConfiguration({ GW_SYNTHETIC_WHIP_TENANT: " " }), journeys),
    /configures an empty/,
  );
});
