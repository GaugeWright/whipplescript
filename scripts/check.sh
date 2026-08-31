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

# Every run keeps its own transcript, because the reflex on a red bar — run it
# again — destroys the only copy of the evidence. That costs nothing on a
# reproducible failure and everything on an intermittent one: a rerun that goes
# green says the flake did not happen this time, never which test failed last
# time. Piping the gate through `tail`/`grep`, which the output volume invites,
# discards it just as completely. So the transcript goes to a file whether the
# run passes or fails, and a failure prints its path.
#
# Kept under `target/` (already ignored) and pruned to the ten most recent, so
# a flake caught on a Tuesday is still readable on a Thursday.
check_log_dir="target/check-logs"
mkdir -p "$check_log_dir"
# The pid disambiguates: the timestamp is second-granular, so two runs started
# in the same second would otherwise name one file and the second would
# truncate the first — losing a transcript exactly when runs come in bursts.
check_log="$check_log_dir/$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)-$$.log"
# `|| true` is load-bearing under `set -euo pipefail`: with no logs yet, the
# glob does not expand, `ls` exits 2, and pipefail would abort the gate on its
# very first run in a fresh checkout.
# `+10`, not `+11`: this prunes before the current run's transcript exists, so
# it leaves nine behind and this run makes ten.
ls -1t "$check_log_dir"/*.log 2>/dev/null | tail -n +10 | xargs -r rm -f || true
# fd 3 is the real terminal, kept so the trap can report the path after the
# transcript is closed.
exec 3>&2
# A named pipe rather than `> >(tee …)`: with process substitution the script
# can exit while tee still holds buffered output, which loses the tail of the
# run — the failure detail — and spills it into the next run's terminal. Naming
# the pipe means the tee has a pid, so the trap can close the write end and
# wait for it to drain.
check_log_fifo="$(mktemp -u)"
mkfifo "$check_log_fifo"
tee "$check_log" < "$check_log_fifo" &
check_log_tee=$!
exec > "$check_log_fifo" 2>&1
# Unlinked immediately; the open descriptors keep it alive, so no path lingers.
rm -f "$check_log_fifo"

# The tracker store otherwise resolves to `.whipplescript/items.sqlite` in the
# working directory, so a check run would share one SQLite file with the
# developer's own tracker and with any concurrent run. Give this run its own.
items_store_root="$(mktemp -d)"
# One EXIT trap, so the cleanup, the transcript drain, and the report share it.
finish() {
    status=$?
    rm -rf "$items_store_root"
    # Restoring stdout/stderr closes the pipe's write end, which is the tee's
    # EOF; without the wait the script can outrun its own transcript.
    exec 1>&3 2>&3
    wait "$check_log_tee" 2>/dev/null || true
    if [ "$status" -ne 0 ]; then
        printf '== check.sh FAILED (status %s) — full transcript: %s ==\n' \
            "$status" "$check_log" >&3
    fi
    exit "$status"
}
trap finish EXIT
export WHIPPLESCRIPT_ITEMS_STORE="$items_store_root/items.sqlite"

# The green bar also runs on the public mirror, which is a curated projection
# rather than an active repository and so does not receive AGENTS.md. The guide
# check applies where the guide exists; that AGENTS.md is present at all in this
# repository is checked from GaugeWright, which owns the shared guidance.
if [ -f AGENTS.md ]; then
    echo "== agent guide =="
    node scripts/check-agent-guide.mjs

    # Same guard, opposite reason: this one needs the FULL tree, because it
    # answers what the projection withheld. Only `-src` can run it — the mirror
    # is the thing being checked, and it cannot see what it is missing
    # (GaugeWright DR-0069 OPS-8 — that repository runs its own DR sequence).
    echo "== mirror projection =="
    node scripts/check-mirror-projection.mjs

    # `-src` only, because `spec/decision-records/` is not projected — the mirror
    # has no records to check the numbering of. A DR number is claimed by writing
    # a file on a branch, so two branches in flight always collide and nothing
    # notices until a person reads the merge; that happened twice on 2026-08-25.
    echo "== decision records =="
    scripts/check-decision-records.sh

    # A conformance suite is worth what it is pointed at. `ContentBlobs` had
    # seven implementations and three ran its suite, and two of the four that
    # did not were minting ids no real backend produces.
    echo "== conformance coverage =="
    scripts/check-conformance-coverage.sh

    # DR-0066 §8 opens "a change that weakens one of these is a defect even when
    # it makes something faster", and not one of its seven refusals had a check.
    # Two are mechanically checkable; the other five are recorded as unchecked
    # rather than left implied.
    echo "== substrate refusals =="
    scripts/check-substrate-refusals.sh

    # Rendered from tools/shared-checks/build-coverage.mjs in the GaugeWright
    # repository, which owns it. It fails when a cargo workspace or a lockfile is
    # watched by nothing. Edit it there and re-render; a local edit fails here.
    #
    # Same guard again, and for the same reason as the guide: what a repository
    # is obliged to compile and audit is a property of the active repository, not
    # of a curated projection that receives neither the rendered check nor the
    # npm trees whose lockfiles are half of those obligations.
    echo "== build coverage =="
    node scripts/check-build-coverage.mjs

    # A filtered `cargo test` exits 0 when its filter matches nothing, so a gate
    # built on one silently stops asserting anything after a rename or crate
    # split (DR-0024). scripts/lib-cargo-test.sh's cargo_test_named closes that,
    # and this static lint keeps the guard from rotting: it fails the bar if any
    # tracked gate script reintroduces a raw filtered run. The --selftest guards
    # the classifier's own logic. Both are toolchain-free static scans, so they
    # belong in the required bar rather than a deep suite.
    echo "== gate test filters are guarded =="
    node scripts/check-cargo-test-guarded.mjs --selftest
    node scripts/check-cargo-test-guarded.mjs
fi

echo "== workflow action pins =="
# Every third-party action must be SHA-pinned, not floating on a tag. The lane
# this most protects is publish-crates.yml, whose job holds the crates.io token
# and cannot be undone. Cheap, needs no toolchain, so it runs on every change.
scripts/check-actions-pinned.sh

# DR-0066: the shared digest/verification cores must stay free of ambient time,
# randomness, and IO, or deterministic simulation stops being available and the
# two hosts become able to disagree. Cheap enough for the green bar; the script
# is explicit about what it does and does not claim.
echo "== sans-IO purity =="
scripts/check-sansio-purity.sh

# The Durable Object's table layout is written out three times -- the worker's
# `do_schema.sql`, the Rust test fixture in `do_store.rs`, and the lazy
# column-adds in `index.ts` -- and nothing checked that they agreed. A column
# added to the fixture alone made every Rust DO test green over a schema
# production does not have (DR-0077's `rule_carries_json`, which surfaced as
# eight session tests reporting 502 with nothing naming a column), and this
# check's first run found `skills.body`, written by `register_skill` and never
# declared on this side at all. Node-only, so it belongs in the required bar.
echo "== durable object schema =="
node scripts/check-do-schema-consistency.mjs --selftest
node scripts/check-do-schema-consistency.mjs

echo "== workstream host contract =="
python3 scripts/check-workstream-host-contract.py

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

echo "== supply-chain policy =="
# What `cargo audit` does not answer: the LICENSES the dependency tree carries,
# whether a crate arrives from an unexpected registry or git remote, and how far
# the tree has duplicated. deny.toml holds the policy; this reads Cargo.lock and
# crate metadata rather than compiling, so it is cheap enough for every change.
# Advisories are left out of the invocation on purpose — `cargo audit` above is
# already the hard advisory gate over the same RustSec database, and a second
# one only adds nondeterministic breakage when a new advisory lands. deny.toml
# says the same at more length.
command -v cargo-deny >/dev/null || {
    echo "cargo-deny is not installed; run: cargo install cargo-deny --locked" >&2
    exit 1
}
cargo deny check bans licenses sources

echo "== formatting =="
cargo fmt --all -- --check

echo "== lints =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== tests =="
cargo test --workspace

# What a release compiles, which is more than what it distributes: every
# workspace member for every target in dist-workspace.toml. The command lives in
# the script below because the `windows-compiles` gate job runs that same script
# rather than a cargo invocation of its own, so the Windows leg cannot drift from
# this bar. On a non-Windows host it says why it cannot answer instead of
# pretending to.
echo "== release compile for windows =="
scripts/check-windows-compile.sh

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

# The OUTPUT printed in the pages, which is the other half of what a page claims
# and had no gate at all: about two dozen `error[code]: …` blocks, with their
# `-->` line, gutter, caret and help. They were hand-written, so when the
# diagnostic rendering changed shape every one went stale at once and each was
# corrected by hand — the same position `examples/invalid/*.diagnostics` was in
# before it was gated. Each sample now names the program it renders from in a
# `<!-- render: … -->` comment and is GENERATED from it, a block whose named code
# the program stopped emitting is a failure rather than an empty sample, and a
# block that looks like compiler output but names no source fails outright, so a
# sample nobody can regenerate cannot be added.
scripts/regen-docs-diagnostics.sh --check

# The other half of the examples corpus: examples/invalid/, whose *.diagnostics
# files are snapshots of what `whip check` actually prints. They were written by
# hand and read by nothing — no test, no script, no gate — so seven of the
# fifteen had rotted against the compiler (a renamed schema, a provider deleted
# in 49e6041, a dropped warning block, line-number drift) and a diagnostic
# regression was invisible. `--check` re-renders each one and fails on any that
# moved, naming the file and the one command that blesses it. The fixture set is
# a glob, so a new examples/invalid/*.whip cannot be forgotten; the script also
# fails when one is absent from the corpus test's hand-maintained include_str!
# list, which is the same self-flattering shape the coverage gate had.
echo "== invalid-fixture diagnostics =="
scripts/regen-invalid-diagnostics.sh --check

# The diagnostic code registers, and the coverage column that makes the code set
# answerable. A second audit of the codes kept finding one-fault-two-codes pairs
# and would not converge, and the reason was measurable: 36 of 163 codes were
# reached by a fixture and 127 by nothing at all, so a misclassification in the
# other 127 was invisible to every gate and could only be found by reading. The
# column turns that from an assumption into a number this gate prints, and the
# governance rule in spec/error-handling.md hangs the append-only guarantee off
# it — a PROVISIONAL code may still be corrected, a COVERED one may not.
#
# It also fails when a code is allocated without its register entry, which is
# what keeps the macro the only door: `DiagnosticCode` has no constructor, so an
# unregistered literal does not compile.
echo "== diagnostic code registers =="
scripts/regen-diagnostic-codes.sh --check

# The vendored `std/` copies. `std/` is the source of truth and each crate
# carries a build-time copy; `crates/whipplescript-parser/build.rs`,
# `crates/whipplescript-cli/src/lib.rs` and `spec/distribution-tracker.md` all
# say this script "fails the gate on drift". Until 2026-08-27 nothing invoked
# it, in check.sh or in any workflow, so those three statements were false and
# a drifted copy would have shipped. Found while adding a manifest entry by
# hand — the same day one of its copies turned out to be missing from the
# script's own map, and therefore checked by nothing at all.
scripts/check-vendored-std.sh

# The tracker registry. `spec/TRACKERS.md` is the status ledger and this script
# is its enforcement, but nothing invoked it — so on 2026-08-27 trunk carried a
# closed tracker with a forward horizon and no gate said so. Found the same day,
# and the same way, as the vendored-std gate above: by running a documented
# check by hand and watching it fail on work that had already merged.
#
# Guarded like the agent guide above and for the same reason: the registry and
# the trackers it indexes live under `spec/`, which the mirror withholds, so
# this can only run where the full tree is.
if [ -f spec/TRACKERS.md ]; then
    scripts/check-trackers.sh
fi

# A check nothing invokes reads exactly like a passing one. This gate is the
# cheap total version of the discipline the mutation sweep applies to refusals:
# it costs milliseconds and it closes the category rather than instances.
#
# The guard is not a mirror carve-out — the projection publishes five workflow
# files, so this runs there too, which is the point. It is for trees that carry
# no workflows at all: with the workflow root absent, every gate a workflow owns
# would read as unreachable and the check would accuse the whole set.
if [ -d .github/workflows ]; then
    scripts/check-gate-reachability.sh
fi

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
