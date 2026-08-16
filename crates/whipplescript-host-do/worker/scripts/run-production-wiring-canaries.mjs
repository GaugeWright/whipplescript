#!/usr/bin/env node
//! Run this repository's production wiring canaries.
//!
//! Until now there was no orchestrator here: `gaugewright-cloud` loaded this
//! manifest as a second owner and ran the suites itself. That coupling refused
//! cloud's entire run over credentials only these suites need, and routed a
//! runtime failure to a repository whose owners do not operate the runtime. Cloud
//! stopped loading it, so this is where the suites run now.

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

/// A runner living in another repository, written `<repo>@<revision>:<path>#<marker>`.
///
/// `public-session` is deliberately one of these: the journey that proves it is
/// cloud's `panels-audience-lifecycle`, at a pinned revision, because the
/// audience half of a published deployment is one journey across both surfaces
/// and splitting it would prove neither end. This lane cannot run such a suite —
/// the runner is not here — so it reports it instead of skipping it, naming
/// where the proof comes from.
export function isDelegated(runner) {
  return /^[a-z0-9-]+@[0-9a-f]{7,40}:/.test(runner ?? "");
}

export function partition(suites) {
  const ready = suites.filter((suite) => suite.state === "ready-awaiting-identity");
  return {
    local: ready.filter((suite) => !isDelegated(suite.runner)),
    delegated: ready.filter((suite) => isDelegated(suite.runner)),
    parked: suites.filter((suite) => suite.state === "awaiting-credentials"),
  };
}

export function missingEnvironment(suites, environment) {
  return [...new Set(suites.flatMap((suite) => suite.requiredEnvironment ?? []))]
    .filter((name) => typeof environment[name] !== "string" || environment[name].trim() === "")
    .sort();
}

function runChild(spawnImpl, command, args, options) {
  return new Promise((resolveChild, reject) => {
    const child = spawnImpl(command, args, options);
    child.once("error", reject);
    child.once("close", (code, signal) => resolveChild({ code, signal }));
  });
}

export async function runProductionWiringCanaries({
  canaries,
  root,
  environment = process.env,
  spawnImpl = spawn,
  selection = "",
}) {
  const { local, delegated, parked } = partition(canaries.suites);
  const requested = selection.trim();
  // `surface:<name>` is what a deploy asks for: everything covering the thing it
  // shipped, without the deploy knowing a suite by name.
  const surface = requested.startsWith("surface:") ? requested.slice("surface:".length) : null;
  const suites = surface
    ? local.filter((suite) => (suite.surfaces ?? []).includes(surface))
    : requested
      ? local.filter((suite) => suite.id === requested)
      : local;
  if (requested && suites.length === 0) {
    const held = [...delegated, ...parked].find((suite) => suite.id === requested);
    if (held) {
      throw new Error(
        `production wiring canary suite ${requested} is not run here: ${
          isDelegated(held.runner)
            ? `its journey is ${held.runner}`
            : `it is parked awaiting credentials`
        }`,
      );
    }
    const covered = [...new Set(local.flatMap((suite) => suite.surfaces ?? []))].sort();
    throw new Error(
      surface
        ? `no runnable production wiring canary covers surface ${surface}; this lane covers ${covered.join(", ")}`
        : `unknown production wiring canary suite: ${requested}`,
    );
  }

  const missing = missingEnvironment(suites, environment);
  if (missing.length > 0) {
    throw new Error(`production wiring credentials are incomplete: ${missing.join(", ")}`);
  }

  const failures = [];
  const executed = [];
  for (const suite of suites) {
    const [locator] = suite.runner.split("#");
    const result = await runChild(spawnImpl, process.execPath, [resolve(root, locator), suite.id], {
      cwd: root,
      env: environment,
      stdio: "inherit",
    });
    executed.push(suite.id);
    if (result.code !== 0) {
      failures.push(`${suite.id} (${result.signal ?? `exit ${result.code}`})`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`production wiring canaries failed: ${failures.join(", ")}`);
  }
  return { executed, delegated, parked };
}

async function main() {
  const root = resolve(import.meta.dirname, "..");
  const canaries = JSON.parse(
    await readFile(resolve(root, "contracts/production-canaries.json"), "utf8"),
  );
  const result = await runProductionWiringCanaries({
    canaries,
    root,
    selection: process.argv[2] ?? "",
  });
  console.log(`Production wiring canaries passed: ${result.executed.join(", ") || "(none selected)"}`);
  for (const suite of result.delegated) {
    console.log(`Proved elsewhere: ${suite.id} — ${suite.runner}`);
  }
  for (const suite of result.parked) {
    console.log(`Parked, awaiting credentials: ${suite.id} — ${suite.reason ?? "no reason recorded"}`);
  }
}

const invoked = process.argv[1]
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) await main();
