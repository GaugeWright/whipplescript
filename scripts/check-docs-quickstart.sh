#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE="$ROOT/.whipplescript/docs-quickstart-smoke.sqlite"
REPORT="$ROOT/target/docs-quickstart-smoke.json"

cleanup() {
  rm -f "$STORE" "$STORE-shm" "$STORE-wal"
}
trap cleanup EXIT

mkdir -p "$ROOT/.whipplescript" "$ROOT/target"
cleanup

WHIP=(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript --)

"${WHIP[@]}" doctor >/dev/null
"${WHIP[@]}" check "$ROOT/examples/multi-agent-bounded-concurrency.whip" >/dev/null
"${WHIP[@]}" --store "$STORE" run "$ROOT/examples/minimal-noop.whip" \
  --provider fixture \
  --until idle \
  --json > "$REPORT"

INSTANCE_ID="$(node -e '
const fs = require("fs");
const text = fs.readFileSync(process.argv[1], "utf8");
const json = JSON.parse(text.slice(text.indexOf("{")));
if (json.workflow !== "MinimalNoop") throw new Error("unexpected workflow");
const first = json.steps && json.steps[0];
if (!first || first.facts_created < 1) throw new Error("expected at least one fact");
console.log(json.instance_id);
' "$REPORT")"

"${WHIP[@]}" --store "$STORE" facts "$INSTANCE_ID" | grep -q "StartupSeen"
"${WHIP[@]}" --store "$STORE" trace "$INSTANCE_ID" --check --json >/dev/null

printf 'docs quickstart smoke passed: %s\n' "$INSTANCE_ID"
