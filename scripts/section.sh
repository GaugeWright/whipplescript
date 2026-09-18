#!/usr/bin/env bash
# The green bar's pure sections, each stated once (GaugeWright BUILD.md, stage 2).
#
#   scripts/section.sh <name>
#
# scripts/check.sh runs a section either directly, through this script, or as
# the Buck2 target of the same name — which also runs this script, in this
# checkout, and re-runs it only when a file the target declares has changed.
# The command lives here and nowhere else. Not here, and never targets: the
# decision-record and host-action-contract sections, which read origin/main
# (the first is the decision-id collision guard, and a cached verdict of it is
# the collision); the advisory and supply-chain sections, which read the world;
# and every section that builds or runs `whip` — the formatter, the lints, the
# feature builds, the tests, the docs and golden regenerations, the hosted
# runtime — which stage 3 owns.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
  agent-guide)          node scripts/check-agent-guide.mjs ;;
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
  *) echo "section.sh: unknown section '${1:-}'" >&2; exit 2 ;;
esac
