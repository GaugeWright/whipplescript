#!/usr/bin/env bash
# Regenerate — or check — the `.diagnostics` snapshots for examples/invalid/*.whip.
#
#   scripts/regen-invalid-diagnostics.sh          rewrite every
#                                                 examples/invalid/<name>.diagnostics
#                                                 from `whip check <name>.whip`
#   scripts/regen-invalid-diagnostics.sh --check  fail (exit 1) if any snapshot is
#                                                 stale or missing, naming the file;
#                                                 rewrites nothing
#
# The snapshots were hand-written and read by nothing — no test, no script, no
# gate — so seven of the fifteen had rotted against the compiler they claim to
# describe (a renamed schema, a provider deleted in 49e6041, a dropped warning
# block, line-number drift). `whip check` reproduces them deterministically, so
# `--check` turns them into a real gate that a diagnostic change has to move on
# purpose, blessed with one command (run this with no args). Without it they
# "looked like goldens but nothing checked them" — the worst of both.
#
# The fixture set is a glob, never a list: a new examples/invalid/*.whip is
# picked up automatically and cannot be forgotten, and a snapshot whose .whip is
# gone is reported as an orphan.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Every path inside a snapshot is the path handed to the binary, so the run has
# to happen from the repository root with a repo-relative argument. Anything
# else bakes this checkout's absolute path into a committed file and the gate
# fails on the next machine.
cd "$ROOT"

# Unlike the IR goldens, the snapshot content IS the binary's stderr, so cargo
# may not share that channel: a "Compiling …" or "Blocking waiting for file
# lock" line would land inside a committed file. Build first (this is the
# "build it if absent" step), then invoke the built binary directly.
cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript
WHIP="${CARGO_TARGET_DIR:-$ROOT/target}/debug/whip"
if [[ ! -x "$WHIP" ]]; then
  echo "no whip binary at $WHIP after a successful build" >&2
  exit 1
fi

# Write mode REWRITES every snapshot, so an unrecognized argument must not fall
# through to it: a typo in a future gate wiring (`--chek`) would otherwise turn
# this gate into a blesser that rewrites every golden and exits 0.
mode="write"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  *)
    echo "usage: scripts/regen-invalid-diagnostics.sh [--check]" >&2
    exit 2
    ;;
esac
if [[ $# -gt 1 ]]; then
  echo "usage: scripts/regen-invalid-diagnostics.sh [--check]" >&2
  exit 2
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# `examples/invalid/*` expands in the shell's collation order, which LC_ALL
# pins, so two machines write the same set in the same order.
export LC_ALL=C

status=0
checked=0
# Orphans first, so a snapshot whose fixture was deleted is named rather than
# left sitting there describing a program that no longer exists.
for snapshot in examples/invalid/*.diagnostics; do
  whip="${snapshot%.diagnostics}.whip"
  if [[ ! -f "$whip" ]]; then
    echo "orphan snapshot (no matching .whip): $snapshot" >&2
    status=1
  fi
done

# The corpus test in crates/whipplescript-parser/src/lib_tests/tests.rs
# (`invalid_fixtures_have_actionable_diagnostics`) names its fixtures in a
# hand-maintained `include_str!` list, because a macro cannot glob a directory.
# A list is exactly the shape that under-counts: add a fixture and the test goes
# on passing over the fifteen it already knew about. This is a glob, so it can
# say what the list is missing. Both modes, because an unlisted fixture is a
# hole whether or not a snapshot is being rewritten.
corpus_test="crates/whipplescript-parser/src/lib_tests/tests.rs"
corpus_fn="invalid_fixtures_have_actionable_diagnostics"
if [[ -f "$corpus_test" ]]; then
  # Scoped to that ONE function's body, not the whole file. A file-wide grep is
  # defeated by the most natural way to add a fixture: mention it in any other
  # test — or in a comment — and the guard passes while the corpus test still
  # walks the set it always knew about. Extract from the fn signature to the
  # next top-level `fn`, and match within that.
  corpus_body="$(awk -v fn="$corpus_fn" '
    index($0, "fn " fn) { inside = 1 }
    inside && /^fn / && index($0, "fn " fn) == 0 { inside = 0 }
    inside { print }
  ' "$corpus_test")"
  if [[ -z "$corpus_body" ]]; then
    echo "corpus test $corpus_fn not found in $corpus_test — this guard is not" >&2
    echo "  checking anything; repoint it at the test that walks examples/invalid/." >&2
    status=1
  fi
  for whip in examples/invalid/*.whip; do
    if ! grep -qF "$whip\"" <<<"$corpus_body"; then
      echo "fixture not in the corpus test: $whip — add an include_str! entry to" >&2
      echo "  invalid_fixtures_have_actionable_diagnostics in $corpus_test" >&2
      status=1
    fi
  done
fi

for whip in examples/invalid/*.whip; do
  snapshot="${whip%.whip}.diagnostics"
  # Auto-detect sibling arguments (examples/invalid/<name>.check-args), for a
  # fixture that needs more than the file — a `--root` when checking one
  # workflow of several, a `--package-lock`. No fixture needs one today:
  # `whip check` checks every workflow a file declares, which the two-workflow
  # recursive-workflow-invocation fixture exercises. The hook exists so that
  # adding such a fixture does not mean rewriting this script.
  args=()
  if [[ -f "${whip%.whip}.check-args" ]]; then
    # shellcheck disable=SC2207 # word splitting is the point: one flag per word
    args=($(cat "${whip%.whip}.check-args"))
  fi
  # stdout and stderr together, in the order a user sees them at a terminal.
  # `whip check` exits non-zero on a refusal — that is the whole point of these
  # fixtures — so the status is deliberately not the failure signal here.
  accepted=0
  "$WHIP" check "$whip" "${args[@]}" >"$tmp" 2>&1 || accepted=$?
  # THE ACCEPTANCE GUARD, and it keys on the exit status rather than on whether
  # anything was printed. Emptiness cannot detect this: `whip check` on a file
  # it ACCEPTS exits 0 and prints an IR dump to stdout, so the captured output is
  # never empty and an emptiness test can never fire. A fixture under
  # examples/invalid/ that the compiler has quietly started accepting is a
  # weakened refusal — the defect this corpus exists to catch — and without this
  # guard write mode would bless the IR dump as the golden and the gate would go
  # green over it.
  if [[ "$accepted" -eq 0 ]]; then
    echo "ACCEPTED: $whip exited 0 — a fixture under examples/invalid/ must be refused." >&2
    echo "  The refusal that rejected it has weakened. Fix the refusal, or move the" >&2
    echo "  fixture out of examples/invalid/ if it is genuinely valid now." >&2
    status=1
    continue
  fi
  checked=$((checked + 1))
  if [[ "$mode" == "check" ]]; then
    if [[ ! -f "$snapshot" ]]; then
      echo "MISSING snapshot: $snapshot — run scripts/regen-invalid-diagnostics.sh" >&2
      status=1
    elif ! diff -q "$tmp" "$snapshot" >/dev/null 2>&1; then
      echo "STALE snapshot: $snapshot — run scripts/regen-invalid-diagnostics.sh" >&2
      status=1
    fi
  else
    cp "$tmp" "$snapshot"
  fi
done

if [[ "$mode" == "check" ]]; then
  [[ "$status" -eq 0 ]] && echo "Invalid-fixture diagnostics OK: $checked snapshots up to date."
else
  echo "Invalid-fixture diagnostics refreshed: $checked snapshots."
fi
exit "$status"
