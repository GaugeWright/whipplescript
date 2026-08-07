#!/usr/bin/env bash
# The green bar for whipplescript-src. This is the complete required check set
# that runs on every change, and the configured CI gate runs this same script,
# so a passing run here and a passing gate cannot mean different things.
#
#   scripts/check.sh
#
# The deep suites — formal models, TLA, end-to-end, report schemas, release
# readiness, and the native provider matrix — are deliberately not here. They
# need Maude, Nix, or live providers and run on their own schedule or dispatch.
# Their entry points remain the individual scripts/check-*.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

# The tracker store otherwise resolves to `.whipplescript/items.sqlite` in the
# working directory, so a check run would share one SQLite file with the
# developer's own tracker and with any concurrent run. Give this run its own.
items_store_root="$(mktemp -d)"
trap 'rm -rf "$items_store_root"' EXIT
export WHIPPLESCRIPT_ITEMS_STORE="$items_store_root/items.sqlite"

echo "== formatting =="
cargo fmt --all -- --check

echo "== lints =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== tests =="
cargo test --workspace

# The hosted Durable Object worker is part of the same per-change gate: its
# production route inventory, authenticated compositions, types, and deployable
# artifact. Missing tooling fails loudly here rather than being skipped quietly.
#
# CI is the one caller that already runs these steps: the
# `hosted-runtime-contracts` job installs the wasm-bindgen/wrangler/Node
# toolchain and runs exactly this sequence. It sets WHIPPLESCRIPT_CHECK_SKIP_HOSTED
# so the green bar does not demand the same toolchain a second time. Nothing
# else should set it — unset, a missing tool is still a hard failure.
echo "== hosted runtime contracts =="
worker=crates/whipplescript-host-do/worker
if [ -n "${WHIPPLESCRIPT_CHECK_SKIP_HOSTED:-}" ]; then
    echo "skipped: WHIPPLESCRIPT_CHECK_SKIP_HOSTED is set (a separate job owns these)"
else
    for tool in wasm-bindgen wrangler; do
        command -v "$tool" >/dev/null 2>&1 || [ -x "$worker/node_modules/.bin/$tool" ] || {
            echo "missing $tool; the hosted runtime contracts are part of the gate" >&2
            exit 1
        }
    done
    [ -d "$worker/node_modules" ] || npm --prefix "$worker" ci
    npm --prefix "$worker" test
    (cd "$worker" && npx tsc --noEmit)
    (cd "$worker" && npx wrangler deploy --config wrangler.public.toml --dry-run --outdir dist-ci)
fi

echo "== whipplescript green bar PASSED =="
