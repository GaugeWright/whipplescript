#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/whip-docs.XXXXXX")"
cleanup() {
  rm -rf "$SMOKE_ROOT"
}
trap cleanup EXIT

STORE="$SMOKE_ROOT/docs-quickstart-smoke.sqlite"
REPORT="$ROOT/target/docs-quickstart-smoke.json"
# Every workspace store belongs to this invocation, including stores inherited
# from the caller's environment. Explicit --store arguments still take priority.
export WHIPPLESCRIPT_STORE="$STORE"
export WHIPPLESCRIPT_COORDINATION_STORE="$SMOKE_ROOT/coordination.sqlite"
export WHIPPLESCRIPT_ITEMS_STORE="$SMOKE_ROOT/items.sqlite"
export WHIPPLESCRIPT_CONTENT_STORE="$SMOKE_ROOT/harness-content.sqlite"
export WHIPPLESCRIPT_IMPROVE_STORE="$SMOKE_ROOT/improve.sqlite"
export WHIPPLESCRIPT_INCIDENTS_STORE="$SMOKE_ROOT/incidents.sqlite"
export WHIPPLESCRIPT_WORKSTREAM_STORE="$SMOKE_ROOT/workstreams.sqlite"
export WHIPPLESCRIPT_BRANCH_STORE="$SMOKE_ROOT/branches.sqlite"
export WHIPPLESCRIPT_VCS_CONTENT_STORE="$SMOKE_ROOT/vcs-content.sqlite"
export WHIPPLESCRIPT_MEMORY_STORE="$SMOKE_ROOT/memory.sqlite"

mkdir -p "$ROOT/target"

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
