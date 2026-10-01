#!/usr/bin/env node
// dispatch: fleet cadence job model-catalog (GaugeWright tools/vmr/manifest.json), daily on a Linux host
//
// Whether the provider catalog the harness's model limits were checked against
// is still the catalog providers publish (WhippleScript DR-0161).
//
//   node scripts/model-catalog.mjs              compare models.dev with the snapshot
//   node scripts/model-catalog.mjs --write      rewrite the snapshot from models.dev
//   node scripts/model-catalog.mjs --from=<file> [--snapshot=<file>] [--write]
//
// crates/whipplescript-kernel/src/model_limits.json states each model's largest
// prompt and, for Claude, its output ceiling. The compaction trigger measures
// against the first and the Anthropic wire sends the second as max_tokens, so
// a number that is too large is refused by the provider and one that is too
// small wastes the window. Providers release models every few weeks, and the
// table had fallen behind several of them before this check existed.
//
// The work is split so the matching rule exists once. Beside the table sits
// model_catalog.json, this script's extract of models.dev for the providers
// the table tracks. The kernel's own tests, in the bar, hold the table to that
// extract through the resolver the runtime uses. This script, run daily by the
// fleet, holds the extract to models.dev itself. It goes red when they differ,
// and the red names the repair. It never edits the table: a number read from a
// community catalog is checked against the provider's own page by whoever
// repairs it, because an overstated output ceiling makes the provider refuse
// every turn on that model.
//
// models.dev unreachable is not a finding about the table. The script says so
// as `#unasserted:` and exits zero, and the fleet's ledger counts it.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SNAPSHOT = join(ROOT, "crates/whipplescript-kernel/src/model_catalog.json");
export const CATALOG_URL = "https://models.dev/api.json";

// The providers model_limits.json tracks, in the order the snapshot lists them.
export const PROVIDERS = ["anthropic", "openai", "xai"];
const LIMIT_FIELDS = ["context", "input", "output"];

/// The models of one models.dev provider that the harness could drive: a model
/// that writes text into a window larger than zero. Image, video and embedding
/// models are not conversation partners and have no window the harness fills.
export function drivable(model) {
  const limit = model?.limit ?? {};
  const outputs = model?.modalities?.output ?? [];
  const family = String(model?.family ?? "");
  return Number(limit.context) > 0 && outputs.includes("text") && !/embedding/.test(family);
}

/// The part of models.dev the snapshot holds: per tracked provider, each
/// drivable model's limits and nothing else, so a catalog edit that cannot
/// change a limit does not redden the job.
export function extract(api) {
  const providers = {};
  for (const provider of PROVIDERS) {
    const models = api?.[provider]?.models;
    if (models === null || typeof models !== "object") {
      throw new Error(`models.dev lists no "${provider}" provider with models; the catalog's shape has changed and this script must be updated to read it`);
    }
    const kept = {};
    for (const id of Object.keys(models).sort()) {
      if (!drivable(models[id])) continue;
      const limit = {};
      for (const field of LIMIT_FIELDS) {
        const value = models[id].limit?.[field];
        if (Number.isInteger(value) && value > 0) limit[field] = value;
      }
      kept[id] = limit;
    }
    providers[provider] = kept;
  }
  return providers;
}

function describe(limit) {
  return LIMIT_FIELDS.filter((field) => field in limit).map((field) => `${field} ${limit[field]}`).join(", ");
}

/// Every difference between two extracts, one line each: `+` a model the
/// catalog now lists, `-` one it no longer does, `~` one whose limits moved.
export function compare(snapshot, live) {
  const lines = [];
  for (const provider of PROVIDERS) {
    const before = snapshot?.[provider] ?? {};
    const after = live?.[provider] ?? {};
    const ids = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    for (const id of ids) {
      if (!(id in before)) lines.push(`+ ${provider}/${id}  ${describe(after[id])}`);
      else if (!(id in after)) lines.push(`- ${provider}/${id}`);
      else if (describe(before[id]) !== describe(after[id])) {
        lines.push(`~ ${provider}/${id}  ${describe(before[id])} -> ${describe(after[id])}`);
      }
    }
  }
  return lines;
}

/// The snapshot as written: one model to a line, so a refresh's diff is one
/// line per model that moved.
export function render(providers, read) {
  const out = [
    "{",
    `  "about": "The models.dev limits of every model a tracked provider lists that writes text. Written by scripts/model-catalog.mjs --write; model_limits.json is held to it by the kernel's tests.",`,
    `  "source": "${CATALOG_URL}",`,
    `  "read": "${read}",`,
    `  "providers": {`,
  ];
  PROVIDERS.forEach((provider, index) => {
    const ids = Object.keys(providers[provider]).sort();
    out.push(`    "${provider}": {`);
    ids.forEach((id, row) => {
      const fields = LIMIT_FIELDS.filter((field) => field in providers[provider][id])
        .map((field) => `"${field}": ${providers[provider][id][field]}`)
        .join(", ");
      out.push(`      ${JSON.stringify(id)}: { ${fields} }${row + 1 < ids.length ? "," : ""}`);
    });
    out.push(`    }${index + 1 < PROVIDERS.length ? "," : ""}`);
  });
  out.push("  }", "}", "");
  return out.join("\n");
}

async function readCatalog(from) {
  if (from) return { api: JSON.parse(readFileSync(from, "utf8")) };
  try {
    const response = await fetch(CATALOG_URL, { signal: AbortSignal.timeout(60_000) });
    if (!response.ok) return { unreachable: `HTTP ${response.status}` };
    return { api: await response.json() };
  } catch (error) {
    return { unreachable: error?.cause?.code ?? error?.name ?? String(error) };
  }
}

async function main(argv) {
  const option = (name) => argv.find((arg) => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
  const write = argv.includes("--write");
  const snapshotPath = option("snapshot") ?? SNAPSHOT;
  const shown = relative(ROOT, snapshotPath) || snapshotPath;

  const { api, unreachable } = await readCatalog(option("from"));
  if (unreachable) {
    console.log(`#unasserted: model-catalog could not read ${CATALOG_URL} (${unreachable}), so ${shown} was not compared with it`);
    return write ? 2 : 0;
  }
  const live = extract(api);

  if (write) {
    writeFileSync(snapshotPath, render(live, new Date().toISOString().slice(0, 10)));
    console.log(`model-catalog: wrote ${shown}. Now run: cargo test -p whipplescript-kernel --lib model_limits`);
    return 0;
  }

  const snapshot = JSON.parse(readFileSync(snapshotPath, "utf8"));
  const drift = compare(snapshot.providers, live);
  if (drift.length === 0) {
    console.log(`model-catalog: ${shown} (read ${snapshot.read}) is still what ${CATALOG_URL} lists for ${PROVIDERS.join(", ")}`);
    return 0;
  }
  console.error(`model-catalog: ${CATALOG_URL} no longer agrees with ${shown} (read ${snapshot.read}):`);
  for (const line of drift) console.error(`  ${line}`);
  console.error([
    "",
    "Repair it like any red main: claim `red main: whipplescript-src` first. Then",
    "  node scripts/model-catalog.mjs --write",
    "  cargo test -p whipplescript-kernel --lib model_limits",
    "and edit crates/whipplescript-kernel/src/model_limits.json until that test passes, checking",
    "each new or changed number against the provider's own model page before you trust it.",
  ].join("\n"));
  return 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      console.error(`model-catalog: ${error.message}`);
      process.exit(2);
    },
  );
}
