#!/usr/bin/env node
// Print the crates.io publish order for this workspace, one crate per line.
//
// crates.io resolves a dependency only if it is already on the index, so the
// workspace has to go up in topological order. Hardcoding that order is how it
// drifts: a new crate, or a new edge between two existing ones, silently keeps
// the old list valid-looking while making it wrong. This derives the order from
// `cargo metadata` every time.
//
// `dev-dependencies` are edges here even though a verification build does not
// compile tests: cargo still has to RESOLVE the published manifest, and a
// versioned dev-dependency that is not on the index fails that resolution. This
// is not hypothetical — `whipplescript-kernel` dev-depends on
// `whipplescript-custodian`, which is why custodian precedes it and why the
// runbook's older five-crate chain was already incomplete.
//
// `publish = false` crates are excluded (whipplescript-host-do).

import { execFileSync } from "node:child_process";

const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  }),
);

const members = new Set(metadata.workspace_members);
const byId = new Map(metadata.packages.map((p) => [p.id, p]));

// Workspace packages that are actually publishable. `publish` is null when
// unrestricted, or an array of allowed registries; an empty array is
// `publish = false`.
const publishable = metadata.packages.filter(
  (p) => members.has(p.id) && (p.publish === null || p.publish.length > 0),
);
const publishableNames = new Set(publishable.map((p) => p.name));

// Edges: crate -> the workspace crates it must follow. Every dependency kind
// counts, for the resolution reason above.
const needs = new Map(
  publishable.map((p) => [
    p.name,
    new Set(p.dependencies.map((d) => d.name).filter((n) => publishableNames.has(n) && n !== p.name)),
  ]),
);

// Kahn, with a name sort inside each layer so the output is stable run to run —
// an unstable order would make a resumed publish look like a different plan.
const order = [];
const remaining = new Map([...needs].map(([n, d]) => [n, new Set(d)]));
while (remaining.size > 0) {
  const ready = [...remaining.entries()]
    .filter(([, deps]) => deps.size === 0)
    .map(([name]) => name)
    .sort();
  if (ready.length === 0) {
    const stuck = [...remaining.entries()].map(([n, d]) => `${n} <- ${[...d].join(", ")}`);
    console.error("cycle among publishable crates; no publish order exists:");
    for (const line of stuck) console.error(`  ${line}`);
    process.exit(1);
  }
  for (const name of ready) {
    order.push(name);
    remaining.delete(name);
  }
  for (const deps of remaining.values()) {
    for (const name of ready) deps.delete(name);
  }
}

if (process.argv.includes("--json")) {
  const version = publishable[0]?.version ?? null;
  console.log(JSON.stringify({ version, order }, null, 2));
} else {
  for (const name of order) console.log(name);
}
