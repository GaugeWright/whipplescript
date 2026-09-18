#!/usr/bin/env bash
# What this bar does about a tool the host has not installed.
#
# Sourced by scripts/check.sh and by scripts/section.sh, which both need it:
# from stage 3 of the Buck2 migration (GaugeWright BUILD.md, DR-0124) a
# section's command lives in section.sh and runs in its own process — under
# Buck2, one that inherits nothing from the shell that asked for it. One copy,
# sourced twice, rather than two that drift.
#
# `prerequisites` arrives from scripts/check.sh: `required` when the gate runs
# the bar, `best-effort` when a developer does. It reaches section.sh as an
# exported variable on the direct path and through the action's key on the
# Buck2 path — the key, because a skip is not a verdict and a run that skipped
# must never be served to one that required an answer. Absent, it is required.
#
# DR-0127 in the GaugeWright repository renders exactly this helper to exactly
# this path across the active repositories. When that rollout reaches here, the
# rendered copy replaces this file.

# Settled here so that a direct `scripts/section.sh <name>` — the Buck2 target's
# path, and an operator's — is a gate rather than an unbound variable.
prerequisites="${prerequisites:-required}"

# $1 the tool, $2 what it gates, $3 the command that installs it,
# $4 the CI job that runs it anyway.
#
# Returns non-zero when the caller must skip, so a guarded step reads
# `if prerequisite …; then`. Under `required` it does not return at all.
prerequisite() {
  command -v "$1" >/dev/null 2>&1 && return 0
  if [ "${prerequisites:-required}" = required ]; then
    echo "$2 requires $1." >&2
    echo "install: $3" >&2
    exit 1
  fi
  echo "-- $2 SKIPPED: $1 is not installed --" >&2
  echo "   the ${4:-check} CI job runs it on every pull request." >&2
  echo "   To close the gap locally: $3" >&2
  return 1
}
