#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHIP="${WHIPPLESCRIPT_BIN:-cargo run -q -p whipplescript --}"
WORKFLOW="$ROOT/examples/queue-gated-smoke.whip"
STORE_DIR="$ROOT/target/queue-gated-smoke"
SUCCESS_STORE="$STORE_DIR/success.sqlite"
SUCCESS_ITEMS="$STORE_DIR/success-items.sqlite"
FAIL_STORE="$STORE_DIR/failure.sqlite"
FAIL_ITEMS="$STORE_DIR/failure-items.sqlite"
SUCCESS_JSON="$STORE_DIR/success.json"
FAIL_JSON="$STORE_DIR/failure.json"

mkdir -p "$STORE_DIR"
rm -f "$SUCCESS_STORE" "$SUCCESS_ITEMS" "$FAIL_STORE" "$FAIL_ITEMS" "$SUCCESS_JSON" "$FAIL_JSON"

run_whip() {
  # shellcheck disable=SC2086
  $WHIP "$@"
}

run_whip check "$WORKFLOW" >/dev/null

WHIPPLESCRIPT_ITEMS_STORE="$SUCCESS_ITEMS" run_whip issue new \
  --tracker backlog --title "Exercise the claim gate" \
  --body "The worker turn is only valid after a successful work-item claim." >/dev/null

WHIPPLESCRIPT_ITEMS_STORE="$SUCCESS_ITEMS" run_whip --store "$SUCCESS_STORE" --json \
  run "$WORKFLOW" --provider fixture --until idle >"$SUCCESS_JSON"

jq -e '
  (.assertions | length) == 4
  and all(.assertions[]; .passed == true)
' "$SUCCESS_JSON" >/dev/null

instance_id="$(jq -r '.instance_id' "$SUCCESS_JSON")"
run_whip --store "$SUCCESS_STORE" --json effects "$instance_id" |
  jq -e '
    ([.[] | select(.kind == "tracker.claim" and .status == "completed")] | length) == 1
    and ([.[] | select(.kind == "agent.tell" and .status == "completed")] | length) == 1
    and ([.[] | select(.kind == "tracker.finish" and .status == "completed")] | length) == 1
  ' >/dev/null

run_whip --store "$SUCCESS_STORE" --json facts "$instance_id" |
  jq -e '
    ([.[] | select(.name == "QueueGatedResult" and (.value.status == "done"))] | length) == 1
    and ([.[] | select(.name == "tracker.claim.completed")] | length) == 1
  ' >/dev/null

WHIPPLESCRIPT_ITEMS_STORE="$SUCCESS_ITEMS" run_whip issue list --tracker backlog | grep -q "WS-1"

printf 'queue gated smoke passed: %s\n' "$instance_id"
