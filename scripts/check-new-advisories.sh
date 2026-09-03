#!/usr/bin/env bash
# An advisory this CHANGE introduces fails. One `main` already carries does not.
#
# The audit used to run in full on every green bar, and that answered the wrong
# question on a pull request. Advisory databases are queried LIVE, so a branch
# that touched no dependency could go red hours after it was pushed, for a
# `fast-uri` advisory published against a transitive dependency of
# `@anthropic-ai/claude-agent-sdk`. That happened on 2026-09-02 and took three
# unrelated pull requests down with it; `339fa43c` records the same shape
# earlier.
#
# This is the ruling `security-baseline.yml` already makes for gitleaks, in its
# own words:
#
#   Does this CHANGE introduce a secret?  -- per pull request, blocking,
#                                            and the author can act on it.
#   Does this REPOSITORY hold a secret?   -- repository health, on main
#                                            and on a schedule.
#
# and the ruling `scripts/check-new-refusals.sh` makes for the mutation sweep.
# The advisory audit is the third instance of that shape and the last one still
# answering the repository question on every branch. The repository question is
# not dropped: the `advisories` job in `security-baseline.yml` runs the FULL
# audit on `main` and on the daily cron, which is where its own header already
# says an advisory published against unchanged code belongs.
#
# Pre-existing advisories are PRINTED, never hidden. A change that inherits a
# red tree should be able to see it without being blocked by it.
#
# dispatch: run by `scripts/check.sh`; run it by hand against your own branch
# with `scripts/check-new-advisories.sh [base-ref]`.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE_REF="${1:-origin/main}"

command -v cargo-audit >/dev/null || {
    echo "cargo-audit is not installed; run: cargo install cargo-audit" >&2
    exit 1
}

if ! BASE="$(git merge-base "$BASE_REF" HEAD 2>/dev/null)"; then
    echo "cannot find a merge base with $BASE_REF" >&2
    exit 2
fi

# On `main` itself the merge base IS the head: nothing can be new, and the
# repository-health question belongs to the `advisories` job. Saying so beats
# running two identical audits to compare a set against itself.
if [[ "$BASE" == "$(git rev-parse HEAD)" ]]; then
    echo "new-advisory check: at the base ref; the full audit runs on main and on the daily cron"
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Advisory identities at one tree state, one per line, as `<ecosystem> <id>`.
#
# The audits' own exit status is NOT the signal: a non-empty advisory set is a
# non-zero exit for both tools, and that exit is the thing being measured here
# rather than an error. What matters is whether a REPORT came back at all --
# `advisory_ids.py` exits 3 when none did, and this treats that as fatal.
#
# It has to. An audit that silently produced nothing gives the same empty set as
# an audit that found nothing, and comparing a real HEAD against an empty BASE
# reports every advisory in the tree as introduced by the branch. That is not
# hypothetical: the first version of this script did exactly that, twice,
# blaming a branch that changed no dependency for two inherited RUSTSEC
# warnings, because the second `cargo audit` of the run intermittently came back
# empty.
audit_or_die() {
    local what="$1"
    shift
    if ! "$@"; then
        echo "could not read the $what advisory report; refusing to guess" >&2
        echo "(a base that cannot be audited makes every advisory look introduced)" >&2
        exit 2
    fi
}

collect() {
    local lock_root="$1" label="$2" stale="$3"
    local report
    if [[ -f "$lock_root/Cargo.lock" ]]; then
        # `--stale` on the second pass: the database was just fetched for the
        # first, and re-fetching it per invocation is what made the second run
        # come back empty.
        report="$(cargo audit --json $stale -f "$lock_root/Cargo.lock" 2>/dev/null </dev/null || true)"
        audit_or_die "$label cargo" \
            bash -c 'printf %s "$1" | python3 scripts/advisory_ids.py cargo' _ "$report"
    fi
    while IFS= read -r lock; do
        local dir="${lock%package-lock.json}"
        dir="${dir%/}"
        local at="$lock_root/${dir:-.}"
        [[ -f "$at/package-lock.json" ]] || continue
        report="$(cd "$at" && npm audit --json --omit=dev 2>/dev/null </dev/null || true)"
        audit_or_die "$label npm ${dir:-.}" \
            bash -c 'printf %s "$1" | python3 "$2/scripts/advisory_ids.py" "npm:$3"' \
            _ "$report" "$ROOT" "${dir:-.}"
    done < <(git ls-files '*package-lock.json')
}

# The base tree's lockfiles, materialised. Only the files the audits read --
# a full worktree checkout would cost a second build directory for nothing.
mkdir -p "$WORK/base"
git show "$BASE:Cargo.lock" >"$WORK/base/Cargo.lock" 2>/dev/null || true
while IFS= read -r lock; do
    dir="${lock%package-lock.json}"
    dir="${dir%/}"
    mkdir -p "$WORK/base/${dir:-.}"
    git show "$BASE:$lock" >"$WORK/base/${dir:-.}/package-lock.json" 2>/dev/null || continue
    git show "$BASE:${dir:+$dir/}package.json" >"$WORK/base/${dir:-.}/package.json" 2>/dev/null || true
done < <(git ls-files '*package-lock.json')

collect "$ROOT" head "" | sort -u >"$WORK/head.txt"
collect "$WORK/base" base --stale | sort -u >"$WORK/base.txt"

introduced="$(comm -23 "$WORK/head.txt" "$WORK/base.txt" || true)"
inherited="$(comm -12 "$WORK/head.txt" "$WORK/base.txt" || true)"

if [[ -n "$inherited" ]]; then
    echo "advisories this branch INHERITS from $BASE_REF (not this change's to fix):"
    sed 's/^/    /' <<<"$inherited"
fi

if [[ -n "$introduced" ]]; then
    echo "advisories this change INTRODUCES:" >&2
    sed 's/^/    /' <<<"$introduced" >&2
    echo >&2
    echo "Each is reachable only because of this branch. Update the dependency, or" >&2
    echo "say in the pull request why it is acceptable." >&2
    exit 1
fi

count=$(wc -l <"$WORK/head.txt")
echo "new-advisory check: no advisory introduced by this change ($count in the tree, all inherited)"
