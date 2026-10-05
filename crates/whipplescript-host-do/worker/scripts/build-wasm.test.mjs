import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import test from "node:test";

// Exercise the real helper with controlled producers. These fixtures qualify
// copy/ordering and node separation; product WASM is qualified by hosted-runtime.
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "whip-release-bindings-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const worker = join(root, "crates/whipplescript-host-do/worker");
  const tools = join(root, "tools");
  mkdirSync(join(worker, "scripts"), { recursive: true });
  mkdirSync(join(worker, "bindings"));
  mkdirSync(tools);
  copyFileSync(new URL("./build-wasm.mjs", import.meta.url), join(worker, "scripts/build-wasm.mjs"));
  const authored = Buffer.from("export function authored(): void;\n");
  const source = join(worker, "bindings/whipplescript_host_do_bg.d.ts");
  writeFileSync(source, authored);
  for (const name of ["cargo", "wasm-bindgen"]) {
    const path = join(tools, name);
    writeFileSync(path, `#!${process.execPath}\n` + `
const fs = require("node:fs"), path = require("node:path");
fs.appendFileSync(process.env.FIXTURE_CALLS, ${JSON.stringify(name)} + " " + JSON.stringify(process.argv.slice(2)) + "\\n");
if (${JSON.stringify(name)} === "wasm-bindgen") {
  const args = process.argv.slice(2), out = args[args.indexOf("--out-dir") + 1];
  fs.mkdirSync(out, {recursive: true});
  fs.writeFileSync(path.join(out, "whipplescript_host_do_bg.d.ts"), "generated declaration\\n");
  fs.writeFileSync(path.join(out, "whipplescript_host_do_bg.wasm"), "synthetic wasm");
  if (process.env.FIXTURE_BINDGEN_FAIL) process.exit(42);
}
`);
    chmodSync(path, 0o755);
  }
  const calls = join(root, "calls.log");
  const run = (args = [], extra = {}) => spawnSync(process.execPath, [join(worker, "scripts/build-wasm.mjs"), ...args], {
    cwd: root,
    env: { PATH: tools + delimiter + process.env.PATH, FIXTURE_CALLS: calls, ...extra },
    encoding: "utf8",
  });
  return { root, worker, source, authored, calls, run };
}

test("cold default bundler copies exact authored declarations after both producers", t => {
  const f = fixture(t), result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readFileSync(join(f.worker, "pkg/whipplescript_host_do_bg.d.ts")), f.authored);
  const calls = readFileSync(f.calls, "utf8").trim().split("\n");
  assert.equal(calls.length, 2);
  assert.match(calls[0], /^cargo .*wasm32-unknown-unknown/);
  assert.match(calls[1], /^wasm-bindgen .*bundler/);
  assert.equal(existsSync(join(f.worker, "pkg-node")), false);
});

test("warm bundler replaces stale output with current authored bytes", t => {
  const f = fixture(t);
  assert.equal(f.run().status, 0);
  const changed = Buffer.from("export function changed(): number;\n");
  writeFileSync(f.source, changed);
  writeFileSync(join(f.worker, "pkg/whipplescript_host_do_bg.d.ts"), "stale");
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readFileSync(join(f.worker, "pkg/whipplescript_host_do_bg.d.ts")), changed);
});

test("missing authored source refuses before producer invocation or warm output mutation", t => {
  const f = fixture(t);
  mkdirSync(join(f.worker, "pkg"));
  writeFileSync(join(f.worker, "pkg/whipplescript_host_do_bg.d.ts"), "retained warm output");
  rmSync(f.source);
  const result = f.run();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ENOENT.*bindings\/whipplescript_host_do_bg\.d\.ts/);
  assert.equal(existsSync(f.calls), false);
  assert.equal(readFileSync(join(f.worker, "pkg/whipplescript_host_do_bg.d.ts"), "utf8"), "retained warm output");
});

test("failed bundler does not finalize authored declarations over failed producer output", t => {
  const f = fixture(t), result = f.run([], { FIXTURE_BINDGEN_FAIL: "1" });
  assert.equal(result.status, 42);
  assert.equal(readFileSync(join(f.worker, "pkg/whipplescript_host_do_bg.d.ts"), "utf8"), "generated declaration\n");
});

test("node target remains independent of authored bundler shim and pkg", t => {
  const f = fixture(t);
  rmSync(f.source);
  const result = f.run(["--node"]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(join(f.worker, "pkg-node/package.json"), "utf8"), '{"type":"commonjs"}\n');
  assert.equal(readFileSync(join(f.worker, "pkg-node/whipplescript_host_do_bg.d.ts"), "utf8"), "generated declaration\n");
  assert.equal(existsSync(join(f.worker, "pkg")), false);
  assert.match(readFileSync(f.calls, "utf8"), /nodejs/);
});
