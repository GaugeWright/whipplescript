#!/usr/bin/env bash
# Find refusals that no test reaches.
#
# The compiler's job is to refuse. A refusal nothing exercises is free to stop
# refusing without any gate noticing, and a check that reports success because
# nothing reached it looks exactly like one that passed. This sweep neutralises
# one refusal at a time and runs the suite; a suite that still passes names an
# unexercised refusal.
#
# Deliberately NOT in scripts/check.sh: one crate rebuild per refusal puts a
# whole file in the hours. Run it against the area you changed, on dispatch.
#
#   scripts/check-mutation-sweep.sh <file> <cargo-test-filter> [limit]
#
# Exits non-zero when it finds an unexercised refusal, or a refusal it could not
# measure because no mutation applied or the mutation did not compile — unknown
# is not covered. So it can gate a subsystem once that subsystem is clean.
set -Eeuo pipefail

mutation_sweep_error() {
  local status=$?
  trap - ERR
  echo "mutation sweep failed at line $1: $2" >&2
  exit "$status"
}
trap 'mutation_sweep_error "$LINENO" "$BASH_COMMAND"' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "$#" -lt 2 ]; then
  echo "usage: scripts/check-mutation-sweep.sh <file> <cargo-test-filter> [limit]" >&2
  echo >&2
  echo "examples:" >&2
  echo "  scripts/check-mutation-sweep.sh \\" >&2
  echo "    crates/whipplescript-kernel/src/package_registry.rs refusal" >&2
  echo "  scripts/check-mutation-sweep.sh \\" >&2
  echo "    crates/whipplescript-parser/src/lib.rs '' 50" >&2
  exit 2
fi

TARGET="$1"
FILTER="$2"
LIMIT="${3:-0}"

# A sweep leaves the tree mutated if it is killed mid-run, and a stale mutation
# reads as a broken build rather than an interrupted sweep. Refuse to start on a
# tree that already has uncommitted changes to the target, so an interrupted run
# is always recoverable with `git checkout -- <file>`.
if ! git diff --quiet -- "$TARGET"; then
  echo "refusing to sweep: $TARGET has uncommitted changes" >&2
  echo "the sweep rewrites this file in place; commit or stash first" >&2
  exit 2
fi

echo "== mutation sweep: $TARGET =="
# A finding is not a crash. Exit 1 means the sweep ran and found unexercised
# refusals — a result to act on, not a broken script — so it must not surface as
# the ERR trap's "failed at line N". Anything else is a genuine failure.
# `set +e` alone is not enough: bash runs the ERR trap on any failing command,
# errexit only controls whether it also exits. A failure handled by `||` does
# not trigger the trap at all, which is what this needs.
STATUS=0
python3 scripts/mutation_sweep.py \
  --target "$TARGET" \
  --filter "$FILTER" \
  --limit "$LIMIT" || STATUS=$?

case "$STATUS" in
  0) echo "== no unexercised refusals in $TARGET ==" ;;
  1) echo "== unexercised or unmeasured refusals found in $TARGET (listed above) ==" ;;
  *) echo "mutation sweep errored (status $STATUS)" >&2 ;;
esac
exit "$STATUS"
