// Tests for scripts/model-catalog.mjs, the fleet's daily model-catalog job.
// Run: node --test scripts/model-catalog.test.mjs
//
// No test reaches models.dev: each one hands the script a catalog file with
// `--from`, so the job's behaviour is checked without a network.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { compare, drivable, extract, render } from "./model-catalog.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "model-catalog.mjs");

const text = (context, output, extra = {}) => ({
  limit: { context, output, ...extra },
  modalities: { input: ["text"], output: ["text"] },
});

function api() {
  return {
    anthropic: { models: { "claude-fable-5-1": text(1_000_000, 128_000) } },
    openai: {
      models: {
        "gpt-6.1-sol": text(1_050_000, 128_000, { input: 922_000 }),
        "text-embedding-3-large": { ...text(8191, 3072), family: "text-embedding" },
        "gpt-image-2": { limit: { context: 0, output: 0 }, modalities: { output: ["image"] } },
      },
    },
    xai: { models: { "grok-4.7": text(500_000, 500_000) } },
    groq: { models: { "llama-3.3-70b": text(128_000, 32_768) } },
  };
}

function run(args, files) {
  const dir = mkdtempSync(join(tmpdir(), "model-catalog-"));
  try {
    for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
    const result = spawnSync(process.execPath, [SCRIPT, ...args.map((arg) => arg.replaceAll("$DIR", dir))], {
      stdio: ["ignore", "pipe", "pipe"],
      encoding: "utf8",
      timeout: 30_000,
      env: { PATH: process.env.PATH ?? "" },
    });
    const snapshot = (() => {
      try {
        return readFileSync(join(dir, "snapshot.json"), "utf8");
      } catch {
        return null;
      }
    })();
    return { ...result, snapshot };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("only models that write text into a window are drivable", () => {
  assert.equal(drivable(text(200_000, 64_000)), true);
  assert.equal(drivable({ ...text(8191, 3072), family: "text-embedding" }), false);
  assert.equal(drivable({ limit: { context: 0 }, modalities: { output: ["image"] } }), false);
  assert.equal(drivable({ limit: { context: 1024 }, modalities: { output: ["video"] } }), false);
});

test("the extract keeps the tracked providers' drivable models and their limits alone", () => {
  assert.deepEqual(extract(api()), {
    anthropic: { "claude-fable-5-1": { context: 1_000_000, output: 128_000 } },
    openai: { "gpt-6.1-sol": { context: 1_050_000, input: 922_000, output: 128_000 } },
    xai: { "grok-4.7": { context: 500_000, output: 500_000 } },
  });
});

test("a catalog without a tracked provider is refused, not read as empty", () => {
  const broken = api();
  delete broken.xai;
  assert.throws(() => extract(broken), /no "xai" provider/);
});

test("a comparison names each added, removed and moved model", () => {
  const before = extract(api());
  const after = structuredClone(before);
  after.openai["gpt-6.2-sol"] = { context: 1_050_000, input: 922_000, output: 128_000 };
  delete after.xai["grok-4.7"];
  after.anthropic["claude-fable-5-1"].output = 256_000;
  assert.deepEqual(compare(before, after), [
    "~ anthropic/claude-fable-5-1  context 1000000, output 128000 -> context 1000000, output 256000",
    "+ openai/gpt-6.2-sol  context 1050000, input 922000, output 128000",
    "- xai/grok-4.7",
  ]);
  assert.deepEqual(compare(before, extract(api())), []);
});

test("the rendered snapshot is JSON that reads back as the extract", () => {
  const providers = extract(api());
  const parsed = JSON.parse(render(providers, "2026-09-30"));
  assert.equal(parsed.read, "2026-09-30");
  assert.deepEqual(parsed.providers, providers);
});

test("the job is green when the snapshot is current and red, with the repair, when it is not", () => {
  const current = render(extract(api()), "2026-09-30");
  const green = run(["--from=$DIR/api.json", "--snapshot=$DIR/snapshot.json"], {
    "api.json": JSON.stringify(api()),
    "snapshot.json": current,
  });
  assert.equal(green.status, 0, green.stderr);
  assert.match(green.stdout, /is still what/);

  const moved = api();
  moved.openai.models["gpt-6.2-sol"] = text(1_050_000, 128_000, { input: 922_000 });
  const red = run(["--from=$DIR/api.json", "--snapshot=$DIR/snapshot.json"], {
    "api.json": JSON.stringify(moved),
    "snapshot.json": current,
  });
  assert.equal(red.status, 1);
  assert.match(red.stderr, /\+ openai\/gpt-6\.2-sol/);
  assert.match(red.stderr, /model-catalog\.mjs --write/);
  assert.match(red.stderr, /cargo test -p whipplescript-kernel --lib model_limits/);
});

test("--write replaces the snapshot with the catalog's current extract", () => {
  const written = run(["--write", "--from=$DIR/api.json", "--snapshot=$DIR/snapshot.json"], {
    "api.json": JSON.stringify(api()),
    "snapshot.json": "{}",
  });
  assert.equal(written.status, 0, written.stderr);
  assert.deepEqual(JSON.parse(written.snapshot).providers, extract(api()));
});
