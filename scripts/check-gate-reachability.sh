#!/usr/bin/env bash
# Every check script must be reachable from something that runs it.
#
# A check that nothing invokes is a gate claiming more than it checks: it
# exists, it is documented, it may even be recorded somewhere as green, and it
# has not run in months. That reads exactly like a passing gate right up until
# someone depends on it. This repository already counts an unexercised refusal
# as a defect while every check is green; an uninvoked CHECK is the same fault
# one level up, and unlike the refusal case it costs milliseconds to rule out.
#
# Found the hard way: `check-queue-gated-smoke.sh` and `check-rule-coverage.sh`
# were both documented and both invoked by nothing.
#
# Reachability is TRANSITIVE from two roots, because a script referenced only by
# an unreachable script is not reachable either:
#
#   1. `scripts/check.sh` — the one required check set.
#   2. any `.github/workflows/*.yml` — a configured gate.
#
# A script that is neither may declare itself an entry point with a
# `# dispatch:` line in its header saying who runs it and why. The declaration
# lives in the script rather than in a list here, so it cannot drift out of
# sync with the thing it describes.
#
# Scope is `check-*.sh`: those are the scripts that claim to enforce something.
# Helpers are libraries, and an uncalled library is dead code rather than a
# false guarantee.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SELF="check-gate-reachability.sh"

# --- the roots -------------------------------------------------------------
declare -A REACHABLE=()
FRONTIER=()

seed() {
  local name="$1"
  [ -f "scripts/$name" ] || return 0
  [ -n "${REACHABLE[$name]:-}" ] && return 0
  REACHABLE["$name"]=1
  FRONTIER+=("$name")
}

seed "check.sh"

# Anything a configured workflow RUNS is a root: the gate invokes it directly.
#
# A `paths:` / `paths-ignore:` filter is not that. It names files whose CHANGE
# should trigger a workflow, which is the opposite claim from "this workflow
# runs it" — and the two are indistinguishable to a bare grep. Found the hard
# way: `sync-public-mirror.yml` lists `scripts/check-lean-models.sh` among the
# paths that trigger a mirror sync, and that mention alone made a gate nothing
# has ever run read as reachable. Same fault as the comment case below, one
# file type over: a mention that looks like a call.
while IFS= read -r name; do
  seed "$name"
done < <(cat .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null \
  | awk '
      { line = $0; sub(/[[:space:]]*#.*$/, "", line) }
      line ~ /^[[:space:]]*(paths|paths-ignore):[[:space:]]*$/ {
        filter_indent = match(line, /[^ ]/) - 1; in_filter = 1; next
      }
      in_filter {
        if (line ~ /^[[:space:]]*$/) next
        if (match(line, /[^ ]/) - 1 > filter_indent) next
        in_filter = 0
      }
      { print line }
    ' \
  | grep -ohE 'check-[a-z0-9-]+\.sh' | sort -u)

# --- transitive walk -------------------------------------------------------
while [ "${#FRONTIER[@]}" -gt 0 ]; do
  current="${FRONTIER[0]}"
  FRONTIER=("${FRONTIER[@]:1}")
  while IFS= read -r name; do
    # A script naming itself in its own usage text is not a caller.
    [ "$name" = "$current" ] && continue
    seed "$name"
    # COMMENTS ARE NOT INVOCATIONS. This checker had that exact bug on its
    # first run: its own header names the two scripts it was written to catch,
    # and the walk read those names as calls and reported everything clean.
    # A mention that looks like a call is the fault this whole gate is about.
  done < <(sed 's/[[:space:]]*#.*$//' "scripts/$current" 2>/dev/null \
    | grep -ohE 'check-[a-z0-9-]+\.sh' | sort -u)
done

# --- verdict ---------------------------------------------------------------
unreachable=()
for path in scripts/check-*.sh; do
  name="$(basename "$path")"
  [ "$name" = "$SELF" ] && continue
  [ -n "${REACHABLE[$name]:-}" ] && continue
  # Self-declared entry point: `# dispatch: <who runs it, and why>`.
  if grep -qE '^# dispatch:' "$path"; then
    continue
  fi
  unreachable+=("$name")
done

if [ "${#unreachable[@]}" -gt 0 ]; then
  echo "gate reachability: ${#unreachable[@]} check script(s) that nothing runs" >&2
  for name in "${unreachable[@]}"; do
    echo "  - scripts/$name" >&2
  done
  echo >&2
  echo "A check nothing invokes reads exactly like a passing one. Either:" >&2
  echo "  * invoke it from scripts/check.sh or a deep-suite script, or" >&2
  echo "  * name it in a .github/workflows/*.yml gate, or" >&2
  echo "  * declare it an entry point with a header line:" >&2
  echo "      # dispatch: <who runs this, and why it is not in the bar>" >&2
  exit 1
fi

total="$(ls scripts/check-*.sh | wc -l | tr -d ' ')"
echo "gate reachability: all $total check scripts are reachable or declared"
