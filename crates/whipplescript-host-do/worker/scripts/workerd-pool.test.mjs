import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { runPool } from "./workerd-pool-runner.mjs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));

test("workerd file isolation survives sequential pool admission", { timeout: 30_000 }, async (context) => {
  // Two tiny files exercise the real Cloudflare pool without building the app.
  const dir = await mkdtemp(resolve(root, "node_modules/.workerd-pool-"));
  const events = resolve(dir, "events.jsonl");
  const fixture = `import { expect, it } from "vitest";
it("keeps its runtime isolated", async () => {
  expect(globalThis.fixtureVisit).toBeUndefined();
  globalThis.fixtureVisit = true;
  await new Promise(resolve => setTimeout(resolve, 750));
});
`;
  let maximumWorkerd = 0;
  try {
    await writeFile(resolve(dir, "first.test.ts"), fixture);
    await writeFile(resolve(dir, "second.test.ts"), fixture);
    await writeFile(resolve(dir, "worker.js"), "export default { fetch() { return new Response('ok'); } };\n");
    await writeFile(resolve(dir, "wrangler.toml"), `name = "workerd-pool-bound"
main = "worker.js"
compatibility_date = "2026-07-24"
`);
    await writeFile(resolve(dir, "reporter.mjs"), `import { appendFileSync } from "node:fs";
export default class {
  onTestCaseReady() { appendFileSync(${JSON.stringify(events)}, '"start"\\n'); }
  onTestCaseResult() { appendFileSync(${JSON.stringify(events)}, '"finish"\\n'); }
}
`);
    await writeFile(resolve(dir, "vitest.config.ts"), `import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { WORKERD_TEST_POOL } from ${JSON.stringify(resolve(root, "src/workerd-test-pool.ts"))};
export default defineConfig({
  root: ${JSON.stringify(dir)},
  plugins: [cloudflareTest({ wrangler: { configPath: ${JSON.stringify(resolve(dir, "wrangler.toml"))} } })],
  test: { ...WORKERD_TEST_POOL, include: ["*.test.ts"], reporters: [${JSON.stringify(resolve(dir, "reporter.mjs"))}] }
});
`);
    let transcript = "";
    // Only process identity/parent/name is sampled; never arguments or buffers.
    const sample = (pid) => {
      const rows = execFileSync("ps", ["-axo", "pid=,ppid=,comm="], { encoding: "utf8", timeout: 1000 }).trim().split("\n").map(line => {
        const match = line.trim().match(/^(\d+)\s+(\d+)\s+(.+)$/);
        return match && { pid: Number(match[1]), parent: Number(match[2]), name: match[3].split("/").at(-1) };
      }).filter(Boolean);
      const descendants = new Set([pid]);
      for (let changed = true; changed;) {
        changed = false;
        for (const row of rows) if (descendants.has(row.parent) && !descendants.has(row.pid)) { descendants.add(row.pid); changed = true; }
      }
      maximumWorkerd = Math.max(maximumWorkerd, rows.filter(row => descendants.has(row.pid) && row.name === "workerd").length);
    };
    const { code } = await runPool({
      command: process.execPath,
      args: [resolve(root, "node_modules/vitest/vitest.mjs"), "run", "--config", resolve(dir, "vitest.config.ts")],
      cwd: root, signal: context.signal,
      sample: ["darwin", "linux"].includes(process.platform) ? sample : undefined,
      onOutput: chunk => { transcript += chunk; },
    });
    assert.equal(code, 0, transcript);
    let active = 0;
    let maximumActive = 0;
    let finished = 0;
    for (const line of (await readFile(events, "utf8")).trim().split("\n")) {
      if (JSON.parse(line) === "start") maximumActive = Math.max(maximumActive, ++active);
      else { --active; ++finished; }
    }
    assert.equal(finished, 2, "both files must execute");
    assert.equal(active, 0, "every started test must finish");
    assert.equal(maximumActive, 1, "file tests must not overlap");
    if (["darwin", "linux"].includes(process.platform)) {
      assert.ok(maximumWorkerd > 0, "must observe a real workerd process");
      assert.equal(maximumWorkerd, 1, "only one fixture runtime may run at once");
    }
    console.log(`bounded synthetic pool: 2 files passed; maximum active tests=${maximumActive}, workerd processes=${maximumWorkerd}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
