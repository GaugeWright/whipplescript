#!/usr/bin/env bash
# Vendored-std drift gate.
#
# Two crates must read the shared `std/` assets from copies inside their own
# crate directory, because a published crate tarball contains ONLY files under
# that directory — a `../../std/...` read builds fine in this workspace and then
# fails the verify build on crates.io. See spec/distribution-tracker.md.
#
# The root `std/` stays the single source of truth. This gate fails if any
# vendored copy has drifted from it, so the duplication cannot rot: edit the
# root file, re-run with --sync, commit both.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# vendored-path<TAB>source-path
MAP=$(cat <<'EOF'
crates/whipplescript-parser/vendored-std/manifests/memory.json	std/manifests/memory.json
crates/whipplescript-parser/vendored-std/manifests/messaging.json	std/manifests/messaging.json
crates/whipplescript-parser/vendored-std/grammars/tracker.json	std/grammars/tracker.json
crates/whipplescript-parser/vendored-std/grammars/coord.json	std/grammars/coord.json
crates/whipplescript-parser/vendored-std/grammars/files.json	std/grammars/files.json
crates/whipplescript-parser/vendored-std/grammars/messaging-grammar.json	std/grammars/messaging-grammar.json
crates/whipplescript-parser/vendored-std/grammars/memory-grammar.json	std/grammars/memory-grammar.json
crates/whipplescript-parser/vendored-std/grammars/vcs-grammar.json	std/grammars/vcs-grammar.json
crates/whipplescript-parser/vendored-std/grammars/custody-grammar.json	std/grammars/custody-grammar.json
crates/whipplescript-parser/vendored-std/manifests/vcs.json	std/manifests/vcs.json
crates/whipplescript-parser/vendored-std/manifests/custody.json	std/manifests/custody.json
crates/whipplescript-cli/vendored-std/manifests/vcs.json	std/manifests/vcs.json
crates/whipplescript-cli/vendored-std/manifests/agent.json	std/manifests/agent.json
crates/whipplescript-cli/vendored-std/manifests/custody.json	std/manifests/custody.json
crates/whipplescript-cli/vendored-std/manifests/agent-codex.json	std/manifests/agent-codex.json
crates/whipplescript-cli/vendored-std/manifests/agent-claude.json	std/manifests/agent-claude.json
crates/whipplescript-cli/vendored-std/manifests/coercion.json	std/manifests/coercion.json
crates/whipplescript-cli/vendored-std/manifests/coord.json	std/manifests/coord.json
crates/whipplescript-cli/vendored-std/manifests/files.json	std/manifests/files.json
crates/whipplescript-cli/vendored-std/manifests/ingress.json	std/manifests/ingress.json
crates/whipplescript-cli/vendored-std/manifests/memory.json	std/manifests/memory.json
crates/whipplescript-cli/vendored-std/manifests/messaging.json	std/manifests/messaging.json
crates/whipplescript-cli/vendored-std/manifests/script.json	std/manifests/script.json
crates/whipplescript-cli/vendored-std/manifests/telemetry.json	std/manifests/telemetry.json
crates/whipplescript-cli/vendored-std/manifests/time.json	std/manifests/time.json
crates/whipplescript-cli/vendored-std/manifests/tracker.json	std/manifests/tracker.json
EOF
)

sync=0
[[ "${1:-}" == "--sync" ]] && sync=1

fail=0
count=0
while IFS=$'\t' read -r vendored source; do
  [[ -z "$vendored" ]] && continue
  count=$((count + 1))
  if [[ ! -f "$source" ]]; then
    echo "VENDORED-STD (hard): source of truth missing: $source" >&2
    fail=1
    continue
  fi
  if [[ ! -f "$vendored" ]]; then
    if (( sync )); then
      mkdir -p "$(dirname "$vendored")"
      cp "$source" "$vendored"
      echo "synced (new): $vendored"
    else
      echo "VENDORED-STD (hard): missing copy $vendored (run scripts/check-vendored-std.sh --sync)" >&2
      fail=1
    fi
    continue
  fi
  if ! cmp -s "$source" "$vendored"; then
    if (( sync )); then
      cp "$source" "$vendored"
      echo "synced: $vendored"
    else
      echo "VENDORED-STD (hard): $vendored has drifted from $source" >&2
      echo "  the root file is the source of truth; run scripts/check-vendored-std.sh --sync" >&2
      fail=1
    fi
  fi
done <<< "$MAP"

# A file added under std/ that a vendoring crate needs will not appear here on
# its own, so also flag any vendored file the map does not know about — that is
# a copy nothing keeps in sync.
while IFS= read -r stray; do
  if ! grep -qF "$stray" <<< "$MAP"; then
    echo "VENDORED-STD (hard): $stray is vendored but not in this gate's map" >&2
    fail=1
  fi
done < <(find crates/*/vendored-std -type f -name '*.json' 2>/dev/null | sort)

if (( fail )); then
  exit 1
fi
echo "vendored-std gate: $count copies match the root std/ source of truth"
