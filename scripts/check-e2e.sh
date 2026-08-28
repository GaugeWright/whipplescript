#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript -- --version >/dev/null
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript -- doctor >/dev/null
cargo test --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript-kernel --test e2e
cargo test --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript --test control_plane

# Example-driven smokes. Both were reachable from nothing until 2026-08-28 and
# both had rotted undetected: the queue-gated smoke still spoke `whip items`,
# `whip dev` and the `queue.*` effect kinds, none of which exist. Wired here
# rather than into the bar because each drives real workflow runs.
"$ROOT/scripts/check-queue-gated-smoke.sh"
"$ROOT/scripts/check-rule-coverage.sh"
