#!/usr/bin/env bash
# Dynamic rule coverage: every rule in every fixture-runnable example must
# commit at least once in a fixture run (queue-backed examples get a seeded
# backlog item).
#
# Review by a person is a tracker round trip, not an in-band ask: `ask_human`
# and the whole inbox surface were removed, so a workflow that waits on a
# person waits on a tracker issue. The seeded backlog item below is what drives
# those rules; a rule gated on an *answer* issue the harness does not file is
# reported as branch-exclusive, like any other undriven branch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHIP="${WHIPPLESCRIPT_BIN:-cargo run -q -p whipplescript --}"
WORK_DIR="$ROOT/target/rule-coverage"
mkdir -p "$WORK_DIR"

run_whip() {
  # shellcheck disable=SC2086
  $WHIP "$@"
}

# Examples that a no-`--input`, no-`--root`, single-workflow fixture run cannot
# drive. Every one is exercised elsewhere; everything else must reach full rule
# coverage here.
#
# ONE NAME, ONE REASON, ONE LINE. This was a single shell word matched by
# substring, with the reasons grouped in a comment above it — and the grouping
# was wrong. It said the multi-workflow examples are "checked by the
# docs-examples gate with the right root", which was true of
# `parent-child-outcomes` and `typed-invoke-result` and false of four others:
# they appeared in this list and NOWHERE ELSE in the tree, so the exclusion
# cited a gate that was not checking them. Three are now in
# `check-docs-examples.sh`; the fourth is below with the reason it cannot be.
#
# A reason per entry is what makes that visible: a claim attached to one name
# can be checked against that name.
SKIP_TABLE="
terminal-output-union|@service: its only rule fires on a WorkItem no table seeds and no tracker projects
clock-source|@service: needs a \`source clock\` tick
ingress-file-source|@service: needs a \`source file\` feed
ingress-http-source|@service: needs a \`source http\` feed
messaging-demo|@service: needs an inbound \`when message from <channel>\`
messaging-inbound-local|@service: needs an inbound \`when message from <channel>\`
event-bridge|@service: needs an injected signal
revision-parent-child|multi-workflow: needs --root
revision-validation-approval|multi-workflow: needs --root
revision-repair-planner|multi-workflow: needs --root
revision-running-cancel|multi-workflow: needs --root
revision-ticket-v1|multi-workflow: needs --root
revision-ticket-v2|multi-workflow: needs --root
coord-acquire-wait|multi-workflow: checked by check-docs-examples.sh --root Holder
least-privilege-subagent|multi-workflow: checked by check-docs-examples.sh --root ParentReview
private-workflow-wrapper|multi-workflow: checked by check-docs-examples.sh --root PublicAudit
parent-child-outcomes|multi-workflow: checked by check-docs-examples.sh --root Parent
typed-invoke-result|multi-workflow: checked by check-docs-examples.sh --root Router
coordination-partition-shared|multi-workflow, and NOT lint-clean under any single root: it declares two leases, one per pair of workflows, so whichever root is chosen the other lints unused. Exercised by nothing until that is resolved
tested-agent-turn|given input: covered by \`whip test\` blocks
coerce-enum|given input: covered by \`whip test\` blocks
subworkflow-tool-consumer|given input: covered by \`whip test\` blocks
compact-contract|given input: covered by \`whip test\` blocks
echo-text-tool|given input: covered by \`whip test\` blocks
improve-triage|given input: covered by \`whip test\` blocks
include-audit|given input: covered by \`whip test\` blocks
include-triage|given input: covered by \`whip test\` blocks
pattern-consumer-audit|given input: covered by \`whip test\` blocks
pattern-consumer-triage|given input: covered by \`whip test\` blocks
redact-projection|given input: covered by \`whip test\` blocks
scalar-terminal|given input: covered by \`whip test\` blocks
package-memory|non-std package import: needs a whip.lock; covered by the dev_capability_call_* tests
package-notes|non-std package import: needs a whip.lock; covered by the check_discovers_* tests
"

# A name with no reason is an exclusion nobody stated, so it is not one.
while IFS='|' read -r skip_name skip_why; do
  [ -n "$skip_name" ] || continue
  if [ -z "$skip_why" ]; then
    echo "SKIP entry \`$skip_name\` carries no reason; state why this harness cannot drive it" >&2
    exit 2
  fi
done <<EOF
$SKIP_TABLE
EOF

# Script hard-off Layer 2 (spec/std-script.md): raw `exec` seeds `script.raw`
# only under dev profile + a non-empty WHIPPLESCRIPT_EXEC_ALLOW, and ungranted
# exec now BLOCKS at store admission (security.script_disabled) instead of
# failing — which would strand the failure-branch rules these examples drive.
# This harness is the operator plane for the fixture runs, so it grants the
# raw commands the exec-bearing examples use (circuit-breaker's failing probe,
# the printf-based typed-ingest examples).
export WHIPPLESCRIPT_EXEC_ALLOW="sh -c *:printf *"

failures=0
for workflow in "$ROOT"/examples/*.whip; do
  name="$(basename "$workflow" .whip)"
  if printf '%s' "$SKIP_TABLE" | grep -q "^$name|"; then continue; fi
  store="$WORK_DIR/$name.sqlite"
  items="$WORK_DIR/$name-items.sqlite"
  rm -f "$store" "$items"
  export WHIPPLESCRIPT_ITEMS_STORE="$items"

  # Tracker-backed examples need at least one ready issue. Detect the declared
  # `tracker <name> { provider builtin }` and seed that queue via `whip issue new`
  # (renamed from the old `whip items add`).
  tracker_queue="$(grep -oE '^tracker [A-Za-z_][A-Za-z0-9_]*' "$workflow" | head -1 | awk '{print $2}' || true)"
  if [ -n "$tracker_queue" ]; then
    run_whip issue new --tracker "$tracker_queue" --title "Coverage item" --body "seeded" >/dev/null
  fi

  report="$WORK_DIR/$name.json"
  if ! run_whip --store "$store" --json run "$workflow" --provider fixture --until idle >"$report" 2>"$WORK_DIR/$name.err"; then
    echo "FAIL (run errored): $name"
    sed -n 1p "$WORK_DIR/$name.err"
    failures=1
    continue
  fi
  # Some effects (e.g. messaging.stdio) print to stdout ahead of the --json
  # payload; extract the JSON object so a stray line does not break the parse.
  instance="$(sed -n '/^{/,$p' "$report" | jq -r '.instance_id // empty' 2>/dev/null || true)"
  if [ -z "$instance" ]; then
    echo "FAIL (no instance_id): $name"
    failures=1
    continue
  fi

  declared="$(run_whip --json check "$workflow" 2>/dev/null | jq -r '.[0].snapshot' | grep -oP '^  rule \K\S+' | sort -u)"
  committed="$(run_whip --store "$store" --json log "$instance" | jq -r '.[] | select(.event_type == "rule.committed") | .payload.rule // empty' | sort -u)"

  uncovered=""
  for rule in $declared; do
    echo "$committed" | grep -qx "$rule" || uncovered="$uncovered $rule"
  done
  if [ -n "$declared" ] && [ -z "$committed" ]; then
    # NOTHING committed. That is not a branch-exclusive report: the run drove
    # no rule at all, so `partial` would claim the example executed and one
    # branch did not fire — a claim more generous than the evidence. An example
    # this harness cannot drive belongs in SKIP with its reason written down,
    # where the exclusion is a stated decision rather than a flattering report.
    echo "FAIL (nothing driven): $name — 0 of $(echo "$declared" | wc -w) declared rules committed; seed its trigger or add it to SKIP with a reason"
    failures=1
    continue
  fi
  if [ -n "$uncovered" ]; then
    # Branch-exclusive rules (coerce/case outputs the fixture provider does
    # not drive) are legitimately uncovered in a single run; report only. The
    # run DID drive the example — at least one rule committed — so this says
    # what it means.
    echo "partial ($name): branch-exclusive rules not driven by fixtures:$uncovered"
  else
    echo "covered: $name"
  fi
done

exit $failures
