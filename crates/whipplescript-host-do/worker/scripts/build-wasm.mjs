import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const nodeTarget = process.argv.includes("--node");
const workerDirectory = resolve(import.meta.dirname, "..");
const workspaceDirectory = resolve(workerDirectory, "../../..");
const targetDirectory = process.env.CARGO_TARGET_DIR
  ? resolve(process.env.CARGO_TARGET_DIR)
  : resolve(workspaceDirectory, "target");

// Authored declarations are a read-only keyed source, not a generated pkg input.
// Read before either producer can mutate output, including on warm builds.
const authoredBindings = nodeTarget ? null : readFileSync(
  resolve(workerDirectory, "bindings/whipplescript_host_do_bg.d.ts"),
);

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

if (!nodeTarget) {
  writeFileSync(resolve(workerDirectory, "pkg/whipplescript_host_do_bg.d.ts"), authoredBindings);
}

if (nodeTarget) {
  writeFileSync(resolve(workerDirectory, "pkg-node/package.json"), '{"type":"commonjs"}\n');
}
