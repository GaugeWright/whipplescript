#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const externalRunners = new Set([
  "gaugewright-cloud@1672ef5a3e7a40b06257d52f14ea6ddf5cb6121f:"
    + "scripts/production-wiring-canary.mjs#panels-audience-lifecycle",
]);
const localRunner = "scripts/production-wiring-canary.mjs";
const allowedStates = new Set(["ready-awaiting-identity", "runner-needed"]);
const allowedBoundaries = new Set([
  "managed-private-home",
  "managed-public-edge",
  "managed-workflow-placement",
]);

export function validateProductionCanaries(manifest, canaries, localRunnerSource = "") {
  assert.equal(canaries.schemaVersion, 1);
  assert.equal(canaries.owner, manifest.owner);
  assert.equal(canaries.activation.orchestratorRepository, "gaugewright-cloud");
  assert.equal(canaries.activation.enabledVariable, "GW_PRODUCTION_WIRING_CANARIES_ENABLED");
  assert.equal(canaries.activation.infisicalPath, "/synthetics/wiring");
  assert.match(canaries.activation.namespace, /^[a-z0-9-]+$/);

  const critical = new Set(manifest.contracts
    .filter((contract) => contract.risk === "critical")
    .map((contract) => contract.id));
  const gaps = new Set(manifest.contracts
    .filter((contract) =>
      contract.risk === "critical" && contract.evidence.deployed.length === 0)
    .map((contract) => contract.id));
  const covered = new Set();
  const suiteIds = new Set();
  let ready = 0;
  let pending = 0;

  for (const suite of canaries.suites) {
    assert.match(suite.id, /^[a-z0-9-]+$/);
    assert(!suiteIds.has(suite.id), `duplicate production canary suite ${suite.id}`);
    suiteIds.add(suite.id);
    assert(allowedStates.has(suite.state), `${suite.id} has invalid state ${suite.state}`);
    assert(
      allowedBoundaries.has(suite.executionBoundary),
      `${suite.id} has invalid execution boundary ${suite.executionBoundary}`,
    );
    assert(Array.isArray(suite.contracts) && suite.contracts.length > 0);
    assert(
      Array.isArray(suite.requiredInfrastructure)
        && suite.requiredInfrastructure.length > 0,
      `${suite.id} has no infrastructure contract`,
    );
    assert.equal(typeof suite.cleanup, "string");
    assert(suite.cleanup.length > 100, `${suite.id} cleanup contract is not explicit`);
    for (const id of suite.contracts) {
      assert(critical.has(id), `${suite.id} maps ${id}, which is not a critical route`);
      assert(!covered.has(id), `${id} is mapped by more than one production canary`);
      covered.add(id);
    }
    if (suite.state === "ready-awaiting-identity") {
      ready += suite.contracts.length;
      assert(Array.isArray(suite.requiredEnvironment) && suite.requiredEnvironment.length > 0);
      for (const name of suite.requiredEnvironment) {
        assert.match(name, /^GW_SYNTHETIC_[A-Z0-9_]+$/);
      }
      const [locator, marker] = String(suite.runner ?? "").split("#");
      if (!externalRunners.has(suite.runner)) {
        assert.equal(locator, localRunner, `${suite.id} has an unapproved runner`);
        assert(marker, `${suite.id} runner has no marker`);
        assert(
          localRunnerSource.includes(`"${marker}"`),
          `${suite.id} local runner marker is absent`,
        );
      }
    } else {
      pending += suite.contracts.length;
      assert.equal(suite.runner, null, `${suite.id} cannot name unimplemented evidence`);
    }
  }

  assert.deepEqual(
    [...gaps].filter((id) => !covered.has(id)).sort(),
    [],
    "production canary map is not exhaustive",
  );
  return {
    gaps: gaps.size,
    covered: covered.size,
    ready,
    pending,
    suites: canaries.suites.length,
  };
}

async function main() {
  const root = resolve(import.meta.dirname, "..");
  const [manifest, canaries, runnerSource] = await Promise.all([
    readFile(resolve(root, "contracts/product-routes.json"), "utf8").then(JSON.parse),
    readFile(resolve(root, "contracts/production-canaries.json"), "utf8").then(JSON.parse),
    readFile(resolve(root, localRunner), "utf8"),
  ]);
  const result = validateProductionCanaries(manifest, canaries, runnerSource);
  console.log(
    `Production canary contract tracks ${result.covered} critical routes in `
      + `${result.suites} suites, including every one of ${result.gaps} routes `
      + `without deployed evidence: ${result.ready} have approved runners awaiting `
      + `identity and ${result.pending} still need a runner.`,
  );
}

const invoked = process.argv[1]
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) await main();
