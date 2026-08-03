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

test("every WhippleScript deployed gap has one cleanup-bounded suite", () => {
  assert.deepEqual(
    validateProductionCanaries(manifest, canaries),
    { gaps: 18, ready: 4, pending: 14, suites: 4 },
  );
});

test("an unmapped operation fails the aggregate", () => {
  const changed = structuredClone(canaries);
  changed.suites[0].contracts.pop();
  assert.throws(
    () => validateProductionCanaries(manifest, changed),
    /production canary map is not exhaustive/,
  );
});

test("a mutable or invented external runner cannot claim evidence", () => {
  const changed = structuredClone(canaries);
  changed.suites[0].runner = "gaugewright-cloud@main:scripts/fake.mjs#public-session";
  assert.throws(
    () => validateProductionCanaries(manifest, changed),
    /approved immutable composed runner/,
  );
});
