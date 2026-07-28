import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const workerDirectory = resolve(import.meta.dirname, "..");
const workspaceDirectory = resolve(workerDirectory, "../../..");
const targetDirectory = process.env.CARGO_TARGET_DIR
  ? resolve(process.env.CARGO_TARGET_DIR)
  : resolve(workspaceDirectory, "target");

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
    resolve(workerDirectory, "pkg"),
    "--target",
    "bundler",
  ],
  workerDirectory,
);
