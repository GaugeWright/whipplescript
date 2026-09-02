#!/usr/bin/env bash
# Regenerate — or check — the `.ir` reference goldens for examples/*.whip.
#
#   scripts/regen-ir-goldens.sh            rewrite every examples/<name>.ir from
#                                          `whip compile examples/<name>.whip`
#   scripts/regen-ir-goldens.sh --check    fail (exit 1) if any golden is stale,
#                                          naming the file; rewrites nothing
#
# `whip compile <file>.whip` deterministically reproduces the golden, so `--check`
# turns the goldens into a real gate (a lowering change that moves a golden fails
# CI) that is blessed with one command (run this with no args). Without `--check`
# the goldens "looked like goldens but nothing checked them" — the worst of both.
#
# A GATE THAT CANNOT PASS BY SHRINKING. Two holes let it do exactly that, and
# both are closed below.
#
#   A failed compile used to print "skip (needs setup the refresher can't
#   supply)" and continue WITHOUT touching `status`. So a lowering regression
#   that stopped an example compiling — the loudest defect this gate exists to
#   catch — exited 0. Compile failure is now a failure. The one deliberate
#   exception is named in EXPECTED_COMPILE_SKIPS, which is empty: every golden's
#   program compiles today from the file plus its auto-detected sibling lock.
#
#   The set of goldens was discovered from the filesystem, so deleting an `.ir`
#   silently shrank the checked set and the run still said OK. GOLDENS records
#   the set by name, and a difference in either direction is an error. This is
#   the shape scripts/check-docs-fences.sh already uses for its per-page counts,
#   for the same reason: dropping coverage must be a deliberate edit here rather
#   than a side effect somewhere else.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHIP=(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript --)

# The examples that carry an `.ir` golden — 25 of the 64 under examples/. The
# rest are exercised by the run-driven gates (docs-examples, rule-coverage, the
# artifact-admission differential) rather than by a lowering snapshot.
GOLDENS=(
  autoresearch-lite
  circuit-breaker
  coerce-branch
  deterministic-validation
  event-bridge
  exec-json-ingest
  expression-kernel
  file-store-demo
  gastown-lite
  improve-triage
  incident-router
  messaging-demo
  minimal-noop
  multi-agent-bounded-concurrency
  openclaw-lite
  package-memory
  provider-language-e2e
  queue-gated-smoke
  queue-worker-with-review
  ralph
  reusable-action-chain
  reusable-review-pattern
  scheduled-escalation
  terminal-output-union
  triage-chain
)

# Examples whose `whip compile` is EXPECTED to fail here because they need setup
# this generic refresher cannot supply (a generated lock, a script manifest).
# Space-separated names, each with its reason written above it. Empty today.
# An entry that in fact compiles is an error, so this cannot rot into a list of
# things that were once broken.
EXPECTED_COMPILE_SKIPS=""

mode="write"
if [[ "${1:-}" == "--check" ]]; then
  mode="check"
fi

tmp="$(mktemp)"
err="$(mktemp)"
trap 'rm -f "$tmp" "$err"' EXIT

status=0
checked=0
skipped=""
seen=""
for ir in "$ROOT"/examples/*.ir; do
  whip="${ir%.ir}.whip"
  name="$(basename "$ir" .ir)"
  seen="$seen $name"
  if [[ ! -f "$whip" ]]; then
    echo "orphan golden (no matching .whip): ${ir#"$ROOT"/}" >&2
    status=1
    continue
  fi
  # Auto-detect a sibling package lock (examples/<name>.lock.json).
  args=()
  if [[ -f "${whip%.whip}.lock.json" ]]; then
    args=(--package-lock "${whip%.whip}.lock.json")
  fi
  # Redirect (not $(...)) so the trailing newline is preserved exactly.
  if ! "${WHIP[@]}" compile "$whip" "${args[@]}" >"$tmp" 2>"$err"; then
    case " $EXPECTED_COMPILE_SKIPS " in
      *" $name "*)
        echo "skip (recorded: needs setup the refresher can't supply): ${whip#"$ROOT"/}" >&2
        skipped="$skipped $name"
        continue
        ;;
    esac
    echo "COMPILE FAILED: ${whip#"$ROOT"/} — its golden cannot be checked, so this is a" >&2
    echo "  lowering regression until proven otherwise. If the example genuinely needs" >&2
    echo "  setup this refresher cannot supply, add it to EXPECTED_COMPILE_SKIPS with" >&2
    echo "  the reason." >&2
    sed 's/^/  | /' "$err" >&2
    status=1
    continue
  fi
  checked=$((checked + 1))
  if [[ "$mode" == "check" ]]; then
    if ! diff -q "$tmp" "$ir" >/dev/null 2>&1; then
      echo "STALE golden: ${ir#"$ROOT"/} — run scripts/regen-ir-goldens.sh" >&2
      status=1
    fi
  else
    cp "$tmp" "$ir"
  fi
done

# The recorded set, checked in both directions.
for name in "${GOLDENS[@]}"; do
  case " $seen " in
    *" $name "*) ;;
    *)
      echo "MISSING golden: examples/$name.ir is recorded in GOLDENS but not present —" >&2
      echo "  the checked set shrank. Restore it, or drop the name from GOLDENS." >&2
      status=1
      ;;
  esac
done
for name in $seen; do
  case " ${GOLDENS[*]} " in
    *" $name "*) ;;
    *)
      echo "UNRECORDED golden: examples/$name.ir is not named in GOLDENS — add it, so" >&2
      echo "  the set this gate covers stays something the script states." >&2
      status=1
      ;;
  esac
done

# A recorded skip that in fact compiles is a stale exemption.
for name in $EXPECTED_COMPILE_SKIPS; do
  case " $skipped " in
    *" $name "*) ;;
    *)
      echo "STALE skip: examples/$name.whip is in EXPECTED_COMPILE_SKIPS but compiled —" >&2
      echo "  drop it from the list so its golden is gated like every other one." >&2
      status=1
      ;;
  esac
done

skipped_count="$(printf '%s' "$skipped" | wc -w | tr -d ' ')"
if [[ "$status" -ne 0 ]]; then
  :
elif [[ "$mode" == "check" ]]; then
  echo "IR goldens OK: $checked examples up to date ($skipped_count skipped)."
else
  echo "IR goldens refreshed: $checked examples ($skipped_count skipped)."
fi
exit "$status"
