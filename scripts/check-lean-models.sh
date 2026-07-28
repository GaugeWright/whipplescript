#!/usr/bin/env bash
# Build the Lean proof layer (models/lean) and enforce that "it compiles" means
# "it is proven": reject any sorry/admit/native_decide/axiom so no theorem can pass
# the gate on an unproven hole. The project is pinned to an installed toolchain and
# uses no Mathlib, so this is hermetic and offline.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEAN_DIR="$ROOT/models/lean"

if ! command -v lake >/dev/null 2>&1; then
  echo "lake (Lean) not found; skipping Lean proof checks" >&2
  exit 1
fi

# Anti-cheat: no unproven holes or trust escapes in the proof sources.
forbidden_re='\bsorry\b|\badmit\b|\bnative_decide\b|^[[:space:]]*axiom\b|\bsorryAx\b'
if grep -REn "$forbidden_re" "$LEAN_DIR/Whipple" "$LEAN_DIR/Whipple.lean"; then
  echo "FAIL: forbidden proof-hole / trust-escape token in Lean sources (see above)" >&2
  exit 1
fi

cd "$LEAN_DIR"
echo "building Lean proofs (pinned $(cat lean-toolchain))..."
lake build

echo "Lean proof layer OK: all theorems proven (no sorry/admit/axiom/native_decide)."
