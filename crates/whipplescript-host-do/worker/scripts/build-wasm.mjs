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

// The Worker shell carries the digest of the final wasm-bindgen artifact into
// Rust's program admission. The wasm cannot embed its own digest without
// changing the bytes being hashed, so generate this beside the exact module
// that Wrangler imports, after either a local build or a cached-package copy.
function writeBundlerArtifactDigest() {
  const out = resolve(workerDirectory, "pkg");
  const bytes = readFileSync(resolve(out, "whipplescript_host_do_bg.wasm"));
  const digest = createHash("sha256").update(bytes).digest("hex");
  writeFileSync(resolve(out, "wasm-artifact-digest.ts"),
    `export const wasmArtifactDigest = ${JSON.stringify(digest)};\n`);
}

// Where the bar hands one over (GaugeWright BUILD.md stage 6): the bundler
// package wasm-bindgen wrote over the native wasm32 build of this crate, from
// the fleet's cache when another host built it. Copied over pkg/ as
// wasm-bindgen's --out-dir writes it, leaving the file pkg/ tracks. The nodejs
// target and every other caller build it here, as always.
const prebuilt = process.env.WHIPPLESCRIPT_HOST_DO_PKG;
if (prebuilt && !nodeTarget) {
  const out = resolve(workerDirectory, "pkg");
  mkdirSync(out, { recursive: true });
  for (const file of readdirSync(prebuilt)) copyFileSync(resolve(prebuilt, file), resolve(out, file));
  writeBundlerArtifactDigest();
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
  writeBundlerArtifactDigest();
}
