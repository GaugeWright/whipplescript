# The `whip` a check runs. Sourced by the bar's documentation and golden
# checks; `$ROOT` is the repository root.
#
# Where the bar hands one over, in WHIPPLESCRIPT_WHIP, it is that: the native
# binary Buck2 built for this tree, or was served from the fleet's cache
# (GaugeWright BUILD.md stage 6; the `native-` sections in BUCK). Otherwise
# cargo builds it, as these checks always did. Either way it is built first and
# run directly: a "Compiling …" or "Blocking waiting for file lock" line on
# cargo's stderr would otherwise land in the output a check captures.
#
#   . "$ROOT/scripts/whip-bin.sh"
#   WHIP="$(whip_bin)"
whip_bin() {
  if [ -n "${WHIPPLESCRIPT_WHIP:-}" ]; then
    printf '%s\n' "$WHIPPLESCRIPT_WHIP"
    return
  fi
  cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript --bin whip >&2
  printf '%s\n' "${CARGO_TARGET_DIR:-$ROOT/target}/debug/whip"
}
