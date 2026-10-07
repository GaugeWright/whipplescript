import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const nodeTarget = process.argv.includes("--node");
const workerDirectory = resolve(import.meta.dirname, "..");
const workspaceDirectory = resolve(workerDirectory, "../../..");
const targetDirectory = process.env.CARGO_TARGET_DIR
  ? resolve(process.env.CARGO_TARGET_DIR)
  : resolve(workspaceDirectory, "target");

// src/index.ts instantiates the wasm itself against the generated `_bg.js`
// glue, and wasm-bindgen's bundler target emits no declaration for that
// module. This one is written beside it rather than tracked in pkg/: pkg/ is
// generated output, writable to the check that builds it and never one of its
// declared inputs, so a tracked file there was read by the typecheck while
// keying nothing. Written here, it is keyed by this script (WS-701).
const BINDINGS_DECLARATION = `export function __wbg_set_wasm(exports: WebAssembly.Exports): void;
export { WasmDurableInstance, exec_lifetime_commands, exec_lifetime_has_settlement_work, exec_lifetime_settle, exec_lifetime_observe, exec_lifetime_retire, exec_provider_claim, exec_provider_resolution, exec_provider_prepare_fence, exec_provider_complete, exec_provider_place, exec_controller_place, exec_controller_transition, exec_barrier_inspect, exec_barrier_begin, exec_barrier_finish, exec_controller_target, exec_controller_result, exec_incarnation_read, exec_incarnation_delivery, exec_incarnation_result, exec_norm_runtime_read, exec_norm_runtime_prepare } from "./whipplescript_host_do";
`;

// The Worker shell carries the digest of the final wasm-bindgen artifact into
// Rust's program admission. The wasm cannot embed its own digest without
// changing the bytes being hashed, so generate this beside the exact module
// that Wrangler imports, after either a local build or a cached-package copy.
function finishBundlerPackage() {
  const out = resolve(workerDirectory, "pkg");
  writeFileSync(resolve(out, "whipplescript_host_do_bg.d.ts"), BINDINGS_DECLARATION);
  const bytes = readFileSync(resolve(out, "whipplescript_host_do_bg.wasm"));
  const digest = createHash("sha256").update(bytes).digest("hex");
  writeFileSync(resolve(out, "wasm-artifact-digest.ts"),
    `export const wasmArtifactDigest = ${JSON.stringify(digest)};\n`);
}

// Where the bar hands one over (GaugeWright BUILD.md stage 6): the bundler
// package wasm-bindgen wrote over the native wasm32 build of this crate, from
// the fleet's cache when another host built it. Copied over pkg/ as
// wasm-bindgen's --out-dir writes it. The nodejs target and every other caller
// build it here, as always.
const prebuilt = process.env.WHIPPLESCRIPT_HOST_DO_PKG;
if (prebuilt && !nodeTarget) {
  const out = resolve(workerDirectory, "pkg");
  mkdirSync(out, { recursive: true });
  for (const file of readdirSync(prebuilt)) copyFileSync(resolve(prebuilt, file), resolve(out, file));
  finishBundlerPackage();
  process.exit(0);
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    env: process.env,
    stdio: "inherit",
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

run(
  "cargo",
  [
    "build",
    "-p",
    "whipplescript-host-do",
    "--no-default-features",
    "--target",
    "wasm32-unknown-unknown",
    "--release",
  ],
  workspaceDirectory,
);

run(
  "wasm-bindgen",
  [
    resolve(
      targetDirectory,
      "wasm32-unknown-unknown/release/whipplescript_host_do.wasm",
    ),
    "--out-dir",
    resolve(workerDirectory, nodeTarget ? "pkg-node" : "pkg"),
    "--target",
    nodeTarget ? "nodejs" : "bundler",
  ],
  workerDirectory,
);

if (nodeTarget) {
  writeFileSync(resolve(workerDirectory, "pkg-node/package.json"), '{"type":"commonjs"}\n');
} else {
  finishBundlerPackage();
}
