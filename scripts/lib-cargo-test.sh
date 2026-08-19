#!/usr/bin/env bash
# Shared helper for the gate scripts that assert a *named* test passes.
#
# `cargo test <filter>` exits 0 when the filter matches nothing. A gate built on
# it therefore keeps passing after the test it names is renamed, deleted, or
# moved to another crate — it stops asserting anything and says nothing about
# having stopped. That is not hypothetical: DR-0024 split the Codex and Claude
# adapters out of `whipplescript-kernel` into their own provider crates, six
# ship-blocking scripts kept `-p whipplescript-kernel`, and nine filters were
# matching zero tests while every one of those scripts reported success.
#
# `cargo_test_named` closes that by listing first and refusing an empty match.
# The point is not that these particular filters are now right — it is that the
# next crate split fails loudly instead of quietly widening the gate.

# cargo_test_named <package> <filter> [extra cargo args...]
#
# Runs `cargo test -p <package> <filter>` after proving the filter selects at
# least one test. Extra args (e.g. `--lib`, `--test control_plane`) are passed to
# both the listing and the run, so the two always agree on scope.
cargo_test_named() {
  local package="$1"
  local filter="$2"
  shift 2

  local matched
  matched="$(cargo test -q -p "$package" "$@" "$filter" -- --list 2>/dev/null \
    | grep -c ': test' || true)"

  if [[ "$matched" == "0" ]]; then
    echo "gate error: '$filter' matches no test in $package ${*:-}" >&2
    echo "  A filter that matches nothing exits 0, so this gate would have" >&2
    echo "  passed while asserting nothing. Repoint it at the crate that owns" >&2
    echo "  the test, or delete the line if the test is genuinely gone." >&2
    return 1
  fi

  cargo test -p "$package" "$@" "$filter"
}
