import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { validateProductionCanaries } from "./check-production-canaries.mjs";

const root = resolve(import.meta.dirname, "..");
const manifest = JSON.parse(await readFile(
  resolve(root, "contracts/product-routes.json"),
  "utf8",
));
const canaries = JSON.parse(await readFile(
  resolve(root, "contracts/production-canaries.json"),
  "utf8",
));
const runnerSource = await readFile(
  resolve(root, "scripts/production-wiring-canary.mjs"),
  "utf8",
);

test("every WhippleScript deployed gap has one cleanup-bounded suite", () => {
  assert.deepEqual(
    validateProductionCanaries(manifest, canaries, runnerSource),
    { gaps: 17, covered: 19, ready: 19, pending: 0, suites: 4 },
  );
});

test("recorded deployed evidence does not unschedule its continuous canary", () => {
  const changed = structuredClone(manifest);
  const firstGap = changed.contracts.find((contract) =>
    contract.risk === "critical" && contract.evidence.deployed.length === 0);
  firstGap.evidence.deployed.push("production:identified-canary-run");
  assert.deepEqual(
    validateProductionCanaries(changed, canaries, runnerSource),
    { gaps: 16, covered: 19, ready: 19, pending: 0, suites: 4 },
  );
});

test("an unmapped operation fails the aggregate", () => {
  const changed = structuredClone(canaries);
  changed.suites[0].contracts.pop();
  assert.throws(
    () => validateProductionCanaries(manifest, changed, runnerSource),
    /production canary map is not exhaustive/,
  );
});

test("a mutable or invented external runner cannot claim evidence", () => {
  const changed = structuredClone(canaries);
  changed.suites[0].runner = "gaugewright-cloud@main:scripts/fake.mjs#public-session";
  assert.throws(
    () => validateProductionCanaries(manifest, changed, runnerSource),
    /unapproved runner/,
  );
});

test("a missing local runner marker cannot claim readiness", () => {
  const changed = structuredClone(canaries);
  changed.suites[1].runner = "scripts/production-wiring-canary.mjs#invented";
  assert.throws(
    () => validateProductionCanaries(manifest, changed, runnerSource),
    /local runner marker is absent/,
  );
});
