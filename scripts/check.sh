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

# The green bar also runs on the public mirror, which is a curated projection
# rather than an active repository and so does not receive AGENTS.md. The guide
# check applies where the guide exists; that AGENTS.md is present at all in this
# repository is checked from GaugeWright, which owns the shared guidance.
if [ -f AGENTS.md ]; then
    echo "== agent guide =="
    node scripts/check-agent-guide.mjs
fi

echo "== production dependency advisories =="
# The audit lives here rather than in a workflow step so that the documented
# local green bar and the enforced gate stay the same command.
command -v cargo-audit >/dev/null || {
    echo "cargo-audit is not installed; run: cargo install cargo-audit" >&2
    exit 1
}
cargo audit
# npm was not audited here until 2026-08-12, and the root tree had six
# production advisories — two high — the whole time. They were not tooling's:
# `scripts/claude-agent-sdk-sidecar.mjs` dynamically imports
# `@anthropic-ai/claude-agent-sdk`, and the shipped `whip` binary executes that
# sidecar, so they sat on a path users run. `git ls-files` names the tracked
# lockfiles, so this audits what the repository owns rather than whatever the
# working tree holds.
while IFS= read -r lock; do
    # The root lockfile comes back as a bare `package-lock.json`, with no
    # directory to strip, so trimming `/package-lock.json` leaves the filename
    # and npm is handed a file where it wants a directory. Strip the name, then
    # the separator, and let an empty result mean the repository root.
    dir="${lock%package-lock.json}"
    dir="${dir%/}"
    npm --prefix "${dir:-.}" audit --omit=dev
done < <(git ls-files '*package-lock.json')

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
echo "== docs =="
# The programs the documentation tells a reader to run are part of the product.
# This checks and lint-cleans every file under examples/ that the docs cite,
# asserts the governance tutorial's programs against their documented pass or
# refusal outcome under each envelope, runs the quickstart end to end against a
# real store, and compiles the tutorial programs (it invokes
# check-docs-quickstart.sh and check-docs-examples.sh
# itself). Until now it lived only in check-release-readiness.sh, a deep suite
# that does not run on a pull request, so a change that broke a documented
# program was caught at release time or not at all.
#
# The programs PRINTED in the pages are checked too, by check-docs-fences.sh:
# every ```whip fence that declares a workflow and carries no ellipsis is
# compiled, and a page that stops contributing one fails on a recorded count, so
# a fence cannot drop out of the set quietly. A fragment — a rule body, a class,
# a `case` arm — is not a program in any grammar and is not compiled; that is
# most of the fences, and it is the honest limit of this gate.
#
# `check-docs-site.sh` (mkdocs --strict, which catches a dead cross-reference)
# stays out: it provisions a virtualenv over the network when mkdocs is absent,
# and a network install inside the required gate costs more in flakiness than
# the class of bug it catches. It remains in the release gate.
scripts/check-docs-snippets.sh
scripts/check-docs-fences.sh

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

    # The workflow prototype ships TypeScript that nothing used to run: `vite
    # build` goes through esbuild, which strips types without checking them, so
    # its compiler was a dependency no gate invoked and its dependency bumps
    # could only ever be assumed green. Typechecking it is cheap and makes them
    # answerable. It shares the guard above because it needs the same Node
    # toolchain the green-bar job deliberately does without.
    prototype=ui/workflow-prototype
    [ -d "$prototype/node_modules" ] || npm --prefix "$prototype" ci
    npm --prefix "$prototype" run typecheck
    # `tsc` never invokes vite, so the typecheck alone says nothing about the
    # build plugins. A vite-plugin-solid bump that cannot compile a component
    # would pass the check above and fail nowhere; building is what covers it.
    npm --prefix "$prototype" run build
fi

echo "== whipplescript green bar PASSED =="
