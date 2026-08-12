#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHIP=(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript --)

check_example() {
  local path="$1"
  shift || true
  "${WHIP[@]}" check "$ROOT/$path" "$@" >/dev/null
  # Examples must also be lint-clean: this dogfoods `whip lint` (any new analysis
  # that false-positives on real code fails here) and keeps the examples free of
  # dead declarations. Lint warnings exit 0, so assert on the findings text.
  local lint_out
  lint_out="$("${WHIP[@]}" lint "$ROOT/$path" "$@" 2>/dev/null || true)"
  if printf '%s' "$lint_out" | grep -q 'warning \[lint'; then
    printf 'lint findings in %s:\n%s\n' "$path" "$lint_out" >&2
    exit 1
  fi
}

check_example examples/minimal-noop.whip
check_example examples/triage-chain.whip
check_example examples/coerce-branch.whip
check_example examples/coerce-enum.whip
check_example examples/terminal-output-union.whip
check_example examples/incident-router.whip
check_example examples/scheduled-escalation.whip
check_example examples/exec-json-ingest.whip
check_example examples/deterministic-validation.whip
check_example examples/redact-projection.whip
check_example examples/event-bridge.whip
check_example examples/messaging-demo.whip
check_example examples/file-store-demo.whip
check_example examples/include-triage.whip
check_example examples/include-audit.whip
check_example examples/parent-child-outcomes.whip --root Parent
check_example examples/compact-contract.whip
check_example examples/scalar-terminal.whip
check_example examples/typed-invoke-result.whip --root Router
check_example examples/pattern-consumer-triage.whip
check_example examples/pattern-consumer-audit.whip
check_example examples/reusable-review-pattern.whip
check_example examples/reusable-action-chain.whip
check_example examples/queue-worker-with-review.whip
check_example examples/multi-agent-bounded-concurrency.whip
check_example examples/circuit-breaker.whip
check_example examples/ralph.whip
check_example examples/owned-harness-demo.whip
check_example examples/echo-text-tool.whip
check_example examples/subworkflow-tool-consumer.whip --package-lock examples/subworkflow-tool-consumer.lock.json --root ConsumerFlow
check_example examples/openclaw-lite.whip
check_example examples/autoresearch-lite.whip
check_example examples/gastown-lite.whip
check_example examples/revision-ticket-v1.whip
check_example examples/revision-ticket-v2.whip
check_example examples/revision-parent-child.whip --root ParentRevisionExample
check_example examples/revision-validation-approval.whip --root RevisionValidation
check_example examples/revision-running-cancel.whip
check_example examples/revision-repair-planner.whip

# The governance tutorial's programs are checked for their *outcome*, not merely
# for compiling: docs/tutorials/governance.md teaches that the same whip passes
# ungoverned and is refused under an envelope, so a gate that only compiled them
# would miss the regression that matters. They also cannot go through
# `check_example`: they grant `**` on their file stores, which `lint.broad_file_grant`
# reports, and narrowing those globs is not what the tutorial is teaching.
#
# `expect` is `pass` or `refuse`; `envelope` is a policy under examples/infoflow/
# or empty for the ungoverned dev-mode reading; `violations` is asserted only
# where the tutorial prints the count in its transcript.
check_governed() {
  local expect="$1"
  local envelope="$2"
  local path="$3"
  local violations="${4:-}"
  local label="$path${envelope:+ under $envelope}"
  local out status=0
  if [ -n "$envelope" ]; then
    out="$(WHIPPLESCRIPT_IFC_ENVELOPE="$ROOT/$envelope" "${WHIP[@]}" check "$ROOT/$path" 2>&1)" || status=$?
  else
    out="$("${WHIP[@]}" check "$ROOT/$path" 2>&1)" || status=$?
  fi
  if [ "$expect" = pass ] && [ "$status" -ne 0 ]; then
    printf 'expected the check of %s to pass; it refused:\n%s\n' "$label" "$out" >&2
    exit 1
  fi
  if [ "$expect" = refuse ] && [ "$status" -eq 0 ]; then
    printf 'expected the check of %s to be refused; it passed:\n%s\n' "$label" "$out" >&2
    exit 1
  fi
  if [ -n "$violations" ] &&
    ! printf '%s' "$out" | grep -q "violations caught in this program: $violations"; then
    printf 'expected %s to report %s violations; the report was:\n%s\n' \
      "$label" "$violations" "$out" >&2
    exit 1
  fi
}

# docs/tutorials/governance.md, in the order the tutorial walks them.
# 1. No envelope is dev mode: the trifecta passes and the check claims nothing.
check_governed pass "" examples/infoflow/support-triage-unsafe.whip
# 3. Under the envelope the same whip is refused, on both halves of the flow.
check_governed refuse examples/infoflow/governance.policy \
  examples/infoflow/support-triage-unsafe.whip 2
# 4. The safe shape passes that same policy with nothing caught.
check_governed pass examples/infoflow/governance.policy \
  examples/infoflow/support-triage-safe.whip 0
# 5. A crossing with a source mark passes only where a grant authorizes it: the
# hatched whip needs the hatches policy, the strict one still refuses it, and a
# grant alone never blesses the unsafe whip.
check_governed pass examples/infoflow/governance-with-hatches.policy \
  examples/infoflow/support-triage-hatched.whip 0
check_governed refuse examples/infoflow/governance.policy \
  examples/infoflow/support-triage-hatched.whip
check_governed refuse examples/infoflow/governance-with-hatches.policy \
  examples/infoflow/support-triage-unsafe.whip 2

printf 'docs examples check + lint passed\n'
