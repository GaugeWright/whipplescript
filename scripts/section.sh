#!/usr/bin/env bash
# Every section of the green bar, each stated once (GaugeWright BUILD.md, stages 2 and 3).
#
#   scripts/section.sh <name>
#
# scripts/check.sh runs a section either directly, through this script, or as
# the Buck2 target of the same name — which also runs this script, in this
# checkout, and re-runs it only when a file the target declares has changed.
# The command lives here and nowhere else. Stage 3 brought in the rest: every
# section that builds or runs `whip` — the formatter, the lints, the feature
# builds, the tests, the docs and golden regenerations, the hosted runtime —
# and the four whose answer is not in this tree at all. Those four are
# `check_world` targets, which refuse to run without a nonce naming the run, so
# they are in the graph without ever being answered from it: the advisory sweep
# and the observer-reactor preparation reach the network, and the decision
# records and the host action contract read origin/main — the first of those is
# the decision-id collision guard, and a cached verdict of it is the collision.
set -euo pipefail
cd "$(dirname "$0")/.."

# What an absent tool means, defined once and sourced by scripts/check.sh too.
# `prerequisites` arrives exported on the direct path and in the action's
# environment on the Buck2 path; absent, it is required, because a skip is not
# a verdict and the gate must never quietly stop gating.
# shellcheck source=scripts/prerequisite.sh
. scripts/prerequisite.sh

# This invocation's own tracker store. Without it the store resolves to
# `.whipplescript/items.sqlite` in the working directory, which a check run
# would share with the developer's own tracker and with any concurrent run.
# scripts/check.sh makes one per run and exports it, and that reaches the
# sections it invokes directly — but a section running as a Buck2 action does
# not inherit that process's environment, so it makes its own here. The
# property is the same either way; only the scope differs.
# One EXIT trap for every temporary root this script makes, because a second
# `trap … EXIT` would replace the first and leak what it was cleaning up.
section_temp_roots=()
section_cleanup() { [ ${#section_temp_roots[@]} -eq 0 ] || rm -rf "${section_temp_roots[@]}"; }
trap section_cleanup EXIT

if [ -z "${WHIPPLESCRIPT_ITEMS_STORE:-}" ]; then
    section_items_root="$(mktemp -d)"
    section_temp_roots+=("$section_items_root")
    export WHIPPLESCRIPT_ITEMS_STORE="$section_items_root/items.sqlite"
fi

# Where anything this section runs writes its temporary files. A Unix-domain
# socket path has a hard length limit — SUN_LEN, 104 bytes on macOS — and the
# CLI tests bind one under $TMPDIR, directly and again through the worker's
# native vector producer. Buck2 gives an action a TMPDIR deep inside buck-out
# (`buck-out/v2/tmp/<cell>/<hash>/<category>/<name>`), long enough on its own to
# push those binds past the limit: the same tests, the same assertions, failing
# on where they were told to write rather than on anything about the change.
#
# So every section says where it writes, in the one place both paths read, and
# `/tmp` is the base because the point is that it is SHORT — it is what
# `env::temp_dir()` falls back to anyway. Removed however this script ends.
#
# On Linux the base is `/dev/shm` instead when it can hold the run: a tmpfs is
# as short a path, and the tests are I/O-bound on the stores they create — a
# SQLite database per fixture, journaled and fsynced — so a disk-backed /tmp
# spends the hosted runner's time in the kernel. GaugeDesk's bar measured the
# same move at 250 s → 148 s for its test phase (gaugedesk-src #697). One
# gigabyte free is the threshold because the whole suite's temporary files
# peak at 219 MB across every parallel test process; the hosted runner's
# /dev/shm is 3.9 GB. Off Linux, or without the room, the base stays `/tmp`
# and the transcript says which it was.
section_tmp_base=/tmp
if [ "$(uname -s)" = Linux ] && [ -d /dev/shm ] && [ -w /dev/shm ]; then
    section_shm_free_kb="$(df -Pk /dev/shm | awk 'NR == 2 { print $4 }')"
    if [ "${section_shm_free_kb:-0}" -ge $((1024 * 1024)) ]; then
        section_tmp_base=/dev/shm
    fi
fi
section_tmpdir="$(mktemp -d "$section_tmp_base/whip-check.XXXXXX")"
section_temp_roots+=("$section_tmpdir")
export TMPDIR="$section_tmpdir"

case "${1:-}" in
  agent-guide)          node scripts/check-agent-guide.mjs ;;
  carries-agent-guide|carries-agent-guide-checker)
    # The cross-repository edge (GaugeWright DR-0124 stage 4). In a workspace
    # the bar builds the `carries` target and never reaches here; reaching here
    # means there is no `gaugewright` cell, so the question cannot be asked.
    echo "#unasserted: $1 needs a materialized workspace; the digest check answered instead"
    echo "-- $1 SKIPPED: no gaugewright cell outside a workspace --" >&2 ;;
  mirror-projection)    node scripts/check-mirror-projection.mjs ;;
  governed-doors)
    scripts/check-governed-doors.sh
    python3 scripts/test-governed-doors.py ;;
  conformance-coverage) scripts/check-conformance-coverage.sh ;;
  substrate-refusals)   scripts/check-substrate-refusals.sh ;;
  build-coverage)       node scripts/check-build-coverage.mjs ;;
  gate-test-filters)
    python3 scripts/test-cargo-test-helper.py
    node scripts/check-cargo-test-guarded.mjs --selftest
    node scripts/check-cargo-test-guarded.mjs ;;
  workflow-action-pins) scripts/check-actions-pinned.sh ;;
  version-pins)
    # Every crate pins its sibling with `version = "X", path = "../…"`; cargo
    # cannot inherit that field, so the pins are hand-maintained copies of
    # [workspace.package] version, and they had drifted (0.5.5 against 0.5.6,
    # hidden by caret semantics). Compare each to the one number.
    ws_version="$(awk -F'"' '/^\[workspace\.package\]/{p=1;next} /^\[/{p=0} p&&/^version *= *"/{print $2;exit}' Cargo.toml)"
    if [ -z "$ws_version" ]; then
        echo "could not read [workspace.package] version out of Cargo.toml" >&2
        exit 1
    fi
    pin_drift="$(grep -n 'path = "\.\./whipplescript-' crates/*/Cargo.toml \
        | grep 'version = "' \
        | grep -v "version = \"$ws_version\"" || true)"
    if [ -n "$pin_drift" ]; then
        echo "intra-workspace pins disagree with [workspace.package] version $ws_version:" >&2
        echo "$pin_drift" >&2
        echo "Bump each to \"$ws_version\"; cargo cannot inherit this field." >&2
        exit 1
    fi ;;
  sansio-purity)        scripts/check-sansio-purity.sh ;;
  do-schema)
    node scripts/check-do-schema-consistency.mjs --selftest
    node scripts/check-do-schema-consistency.mjs ;;
  workstream-host-contract) python3 scripts/check-workstream-host-contract.py ;;
  refusal-scanner)      python3 scripts/test-mutation-sweep.py ;;
  vendored-std)         scripts/check-vendored-std.sh ;;
  trackers)             scripts/check-trackers.sh ;;
  gate-reachability)    scripts/check-gate-reachability.sh ;;
  decision-records)     scripts/check-decision-records.sh ;;
  host-action-contract)
    python3 scripts/check-host-action-contract.py
    python3 scripts/test-host-action-contract.py
    python3 scripts/check-host-action-contract-v2.py
    python3 scripts/test-host-action-contract-v2.py
    python3 scripts/check-host-action-contract-v3.py
    python3 scripts/test-host-action-contract-v3.py
    python3 scripts/check-host-action-contract-v4.py
    python3 scripts/test-host-action-contract-v4.py ;;
  advisories)           scripts/check-new-advisories.sh ;;
  supply-chain)
    if prerequisite cargo-deny "the supply-chain policy check" \
            "cargo install cargo-deny --locked" "check"; then
        cargo deny check bans licenses sources
    fi ;;
  formatting)           cargo fmt --all -- --check ;;
  lints)                cargo clippy --workspace --all-targets -- -D warnings ;;
  feature-builds)
    cargo check -p whipplescript-store --no-default-features
    cargo check -p whipplescript-kernel --no-default-features
    cargo check -p whipplescript --no-default-features
    # whipplescript-custodian's `pkcs11` gates eight cfg sites and was compiled
    # by nothing. cryptoki loads its vendor module at runtime and its bindings
    # are pre-generated, so this needs no system library and is portable. Its
    # sibling `tpm` is deliberately NOT here: tss-esapi links the native tss2
    # stack, so the check would pass on a box with libtss2-dev and fail
    # everywhere else — a gate that means two different things in two places.
    cargo check -p whipplescript-custodian --features pkcs11 --all-targets ;;
  norm-observer)
    norm_host="$(uname -s)-$(uname -m)"
    case "$norm_host" in
      Linux-x86_64 | Linux-amd64)
        python3 experiments/norm-wasi/prepare.py --fetch
        python3 experiments/norm-wasi/preparation_checks.py ;;
      *)
        echo "skipped: the observer reactor builder requires a Linux x86-64 host, and this is $norm_host;"
        echo "         the green-bar CI job runs this same script on ubuntu-latest and prepares it there" ;;
    esac ;;
  tests)
    if command -v cargo-nextest >/dev/null 2>&1; then
        cargo nextest run --workspace
    else
        cargo test --workspace
    fi ;;
  buck2-test-executor)
    # BE-02 of the admission fixtures: the test executor of DR-0124 §14.5
    # against a real Buck2 over examples/buck2-tests. The test is ignored
    # under the ordinary `tests` unit because it needs buck2 on the PATH;
    # this unit runs it where buck2 is, and names the remedy where it is not.
    if prerequisite buck2 "the Buck2 test-executor fixture" \
        "scripts/install-buck2.sh in the GaugeWright repository, which installs the pinned release" \
        buck2-test-executor; then
        if command -v cargo-nextest >/dev/null 2>&1; then
            cargo nextest run -p whipplescript-test-executor --test buck2 --run-ignored all
            cargo nextest run -p whipplescript --run-ignored all -E 'test(/build_engine::/)'
        else
            cargo test -p whipplescript-test-executor --test buck2 -- --ignored
            cargo test -p whipplescript --bin whip -- --ignored build_engine::
        fi
    fi ;;
  windows-compile)      scripts/check-windows-compile.sh ;;
  docs)
    scripts/check-docs-snippets.sh
    scripts/check-docs-fences.sh
    scripts/regen-docs-diagnostics.sh --check ;;
  invalid-diagnostics)  scripts/regen-invalid-diagnostics.sh --check ;;
  ir-goldens)           scripts/regen-ir-goldens.sh --check ;;
  diagnostic-codes)     scripts/regen-diagnostic-codes.sh --check ;;
  hosted-runtime)
  worker=crates/whipplescript-host-do/worker
  # The hard exit here named neither a remedy nor the job that does run this,
  # so a workstation without the wasm toolchain got a red bar that said only
  # that it was a workstation. `wrangler` arrives with the worker's own
  # node_modules, so an absent one is often just an uninstalled tree.
  missing_hosted=""
  for tool in wasm-bindgen wrangler; do
      command -v "$tool" >/dev/null 2>&1 || [ -x "$worker/node_modules/.bin/$tool" ] \
          || missing_hosted="${missing_hosted:+$missing_hosted }$tool"
  done

  hosted_install="cargo install wasm-bindgen-cli --locked, and npm --prefix $worker ci"
  if [ -z "$missing_hosted" ]; then
      [ -d "$worker/node_modules" ] || npm --prefix "$worker" ci
      npm --prefix "$worker" test
      (cd "$worker" && npx tsc --noEmit)
      # Cosmetic requests must not hold the gate open after the dry-run.
      # Wrangler's banner stops waiting for its update lookup without
      # cancelling the request.
      (cd "$worker" && WRANGLER_HIDE_BANNER=true WRANGLER_SEND_METRICS=false \
          npx wrangler deploy --config wrangler.public.toml --dry-run --outdir dist-ci)
  elif [ "$prerequisites" = required ]; then
      echo "the hosted runtime contracts require:$missing_hosted" >&2
      echo "install: $hosted_install" >&2
      exit 1
  else
      echo "-- hosted runtime contracts SKIPPED: missing$missing_hosted --" >&2
      echo "   the hosted-runtime-contracts CI job has this toolchain and runs them on" >&2
      echo "   every pull request. To close the gap locally: $hosted_install" >&2
  fi ;;
  *) echo "section.sh: unknown section '${1:-}'" >&2; exit 2 ;;
esac
