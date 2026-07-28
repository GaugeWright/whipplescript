#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LENGTH="${WHIPPLESCRIPT_TLA_LENGTH:-6}"

if command -v apalache-mc >/dev/null 2>&1; then
  APALACHE=(apalache-mc)
else
  if command -v nix >/dev/null 2>&1; then
    APALACHE=(nix --extra-experimental-features 'nix-command flakes' develop "$ROOT" --command apalache-mc)
  else
    echo "apalache-mc not found and nix is unavailable" >&2
    exit 1
  fi
fi

for MODEL in "$ROOT/models/tla/ControlPlaneLifecycle.tla" "$ROOT/models/tla/NativeProviderLifecycle.tla" "$ROOT/models/tla/ResumableEffectLifecycle.tla" "$ROOT/models/tla/InstanceSchedulerLifecycle.tla" "$ROOT/models/tla/ClockSourceLifecycle.tla" "$ROOT/models/tla/InfoflowReleaseBudget.tla" "$ROOT/models/tla/InfoflowLabelCarriage.tla" "$ROOT/models/tla/ReconciliationDaemonLifecycle.tla" "$ROOT/models/tla/CoordLease.tla" "$ROOT/models/tla/CoordCounter.tla" "$ROOT/models/tla/CoordLedger.tla"; do
  "${APALACHE[@]}" typecheck "$MODEL"
  "${APALACHE[@]}" check \
    --cinit=ConstInit \
    --init=Init \
    --next=Next \
    --inv=SafetyInvariants \
    --length="$LENGTH" \
    "$MODEL"
done

# --- Requeue-necessity bite (see models/tla/EffectRequeueNecessity.tla) -----------
# ControlPlaneLifecycle enforces "a blocked effect must be requeued before it can be
# claimed" structurally, via ClaimEffect's `effects[e] = "queued"` guard, but no
# state invariant there is *violated* if that guard is weakened (claim-from-blocked
# leaves no bad state, only a bad step, and Apalache 0.56 has no --trace-inv). This
# focused model gives the necessity real teeth with a history variable, and we prove
# the guard is load-bearing by mutation.
REQ_MODEL="$ROOT/models/tla/EffectRequeueNecessity.tla"
echo "== requeue-necessity: correct model must hold"
"${APALACHE[@]}" typecheck "$REQ_MODEL"
"${APALACHE[@]}" check --init=Init --next=Next --inv=Invariants --length=6 "$REQ_MODEL"

echo "== requeue-necessity: mutant (guard dropped) must be caught"
MUT_DIR="$(mktemp -d)"
trap 'rm -rf "$MUT_DIR"' EXIT
awk '
  /^Claim ==/ {inclaim=1}
  inclaim && /status = "queued"/ {print "  \\* MUTANT: guard removed"; inclaim=0; next}
  {print}
' "$REQ_MODEL" > "$MUT_DIR/EffectRequeueNecessity.tla"
if "${APALACHE[@]}" check --init=Init --next=Next --inv=Invariants --length=6 \
      "$MUT_DIR/EffectRequeueNecessity.tla" > "$MUT_DIR/out.log" 2>&1; then
  echo "requeue-necessity bite FAILED: the guard-dropped mutant did not violate ClaimsOnlyFromQueued" >&2
  exit 1
fi
if ! grep -qiE 'invariant .* violated|outcome is: Error' "$MUT_DIR/out.log"; then
  echo "requeue-necessity bite FAILED: mutant erred for the wrong reason (not an invariant violation)" >&2
  cat "$MUT_DIR/out.log" >&2
  exit 1
fi
echo "requeue-necessity bite OK (guard is load-bearing)"

# The main spec's guard must actually be present for the bite above to protect it.
echo "== requeue-necessity: ControlPlaneLifecycle Claimable retains its queued guard"
if ! grep -Eq 'effects\[e\] = "queued"' "$ROOT/models/tla/ControlPlaneLifecycle.tla"; then
  echo "ControlPlaneLifecycle.tla no longer guards ClaimEffect on effects[e] = \"queued\"" >&2
  exit 1
fi

# --- std.coord protocol bites (spec/std-coord.md v1 slice 1) ----------------------
# Each coord model's load-bearing guard is proven by mutation: with the guard
# awk-stripped, Apalache must find an invariant violation (MutualExclusion /
# CapInvariant / NoLostEntry respectively). A mutant that stays green means the
# invariant lost its teeth.
coord_bite() {
  local model="$1" guard_re="$2" what="$3"
  local dir
  dir="$(mktemp -d)"
  awk -v re="$guard_re" '$0 ~ re { print "  \\* MUTANT: guard removed"; next } { print }' \
    "$ROOT/models/tla/$model.tla" > "$dir/$model.tla"
  echo "== coord bite: $model ($what) mutant must be caught"
  if "${APALACHE[@]}" check --cinit=ConstInit --init=Init --next=Next \
        --inv=SafetyInvariants --length=6 "$dir/$model.tla" > "$dir/out.log" 2>&1; then
    echo "coord bite FAILED: $model guard-dropped mutant did not violate $what" >&2
    rm -rf "$dir"
    exit 1
  fi
  if ! grep -qiE 'invariant .* violated|outcome is: Error' "$dir/out.log"; then
    echo "coord bite FAILED: $model mutant erred for the wrong reason (not an invariant violation)" >&2
    cat "$dir/out.log" >&2
    rm -rf "$dir"
    exit 1
  fi
  rm -rf "$dir"
  echo "coord bite OK ($model $what guard is load-bearing)"
}
coord_bite CoordLease   'Cardinality\(held\[k\]\) < Slots' MutualExclusion
coord_bite CoordCounter 'consumed \+ a <= Cap'             CapInvariant
# NB: no backslashes in the pattern — awk -v escape processing would eat them
# (\\n becomes a newline in a gawk dynamic regex and silently never matches).
coord_bite CoordLedger  'notin appended'                   NoLostEntry
