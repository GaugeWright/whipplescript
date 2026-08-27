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

for MODEL in "$ROOT/models/tla/ControlPlaneLifecycle.tla" "$ROOT/models/tla/NativeProviderLifecycle.tla" "$ROOT/models/tla/ResumableEffectLifecycle.tla" "$ROOT/models/tla/InstanceSchedulerLifecycle.tla" "$ROOT/models/tla/ClockSourceLifecycle.tla" "$ROOT/models/tla/InfoflowReleaseBudget.tla" "$ROOT/models/tla/InfoflowLabelCarriage.tla" "$ROOT/models/tla/ReconciliationDaemonLifecycle.tla" "$ROOT/models/tla/CoordLease.tla" "$ROOT/models/tla/CoordCounter.tla" "$ROOT/models/tla/CoordLedger.tla" "$ROOT/models/tla/CredentialCustody.tla" "$ROOT/models/tla/LogChainIntegrity.tla" "$ROOT/models/tla/PinnedResolution.tla" "$ROOT/models/tla/SubstratePublishOrder.tla"; do
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
  local model="$1" guard_text="$2" what="$3"
  local dir
  dir="$(mktemp -d)"
  awk -v text="$guard_text" \
    'index($0, text) { print "  \\* MUTANT: guard removed"; next } { print }' \
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
coord_bite CoordLease   'Cardinality(held[k]) < Slots' MutualExclusion
# DR-0076 P5: TerminalRelease needs its own teeth, and its load-bearing guard is
# the one that keeps a terminated holder from acquiring again -- without it the
# terminal's release is undone a step later and the bound means nothing. Matched
# as 'notin terminated' rather than 'h \notin terminated' for the reason the
# CredentialCustody section below documents at length: awk's -v unescapes once,
# and \n is a known escape, so the backslash form would become a newline in both
# awks and match nothing. The substring hits the guard in Acquire and Deny (and
# the double-terminate guard, harmlessly); Acquire's is the one that bites.
coord_bite CoordLease   'notin terminated'            TerminalRelease

# TerminalRelease says a terminated holder holds no slot ON ANY KEY, and that is
# only distinguishable from a per-key release when Keys has more than one
# element. Neither the base check nor the bite above notices a one-key ConstInit:
# with Keys = {"k1"} a Terminate freeing only k1 still satisfies the invariant,
# and the guard-dropped mutant still violates it, so both stay green while the
# across-all-keys content is gone. Guard the constant directly.
echo "== coord: CoordLease ConstInit must carry more than one key"
COORD_KEYS="$(awk '/^ConstInit ==/{f=1} f && /Keys =/{gsub(/.*\{|\}.*/,""); n=split($0, a, ","); print n; exit}' "$ROOT/models/tla/CoordLease.tla")"
if [[ -z "$COORD_KEYS" || "$COORD_KEYS" -lt 2 ]]; then
  echo "CoordLease.tla ConstInit carries ${COORD_KEYS:-0} key(s); TerminalRelease's across-all-keys claim is vacuous below two" >&2
  exit 1
fi
echo "coord OK (CoordLease ConstInit carries $COORD_KEYS keys)"
coord_bite CoordCounter 'consumed + a <= Cap'           CapInvariant
coord_bite CoordLedger  'notin appended'                   NoLostEntry

# --- DR-0067 log-chain bites (models/tla/LogChainIntegrity.tla) ------------------
# The append carries TWO guards, and the claim in DR-0067 section 3 is that
# neither subsumes the other: compare-and-set defeats a blind zombie, the owner
# epoch defeats one that re-read the head first. So each guard gets its own
# bite, and they must violate DIFFERENT invariants -- a shared violation would
# mean one guard is riding on the other's teeth and the pair is really one.
#
# Both guards are structural conjuncts of WriteEntry, so a violating step simply
# cannot be taken and no state invariant would notice. The model carries a
# history variable per guard (`staleWrite`, `blindWrite`) for exactly that
# reason, as EffectRequeueNecessity does for the requeue guard.
# Generic marker bite: delete the line carrying MARKER from MODEL and require an
# invariant violation. The mutant is compared against the original first, so a
# marker that has been renamed away cannot let a bite silently test nothing —
# the failure mode the custody bites below paid for.
marker_bite() {
  local model="$1" marker="$2" expect_inv="$3"
  local dir
  dir="$(mktemp -d)"
  grep -v "$marker" "$ROOT/models/tla/$model.tla" > "$dir/$model.tla"
  if cmp -s "$dir/$model.tla" "$ROOT/models/tla/$model.tla"; then
    echo "$model bite FAILED: marker '$marker' matched nothing, so it tested nothing" >&2
    rm -rf "$dir"
    exit 1
  fi
  echo "== $model bite: mutant without '$marker' must violate $expect_inv"
  if "${APALACHE[@]}" check --cinit=ConstInit --init=Init --next=Next \
        --inv=SafetyInvariants --length=6 "$dir/$model.tla" \
        > "$dir/out.log" 2>&1; then
    echo "$model bite FAILED: dropping '$marker' did not violate $expect_inv" >&2
    rm -rf "$dir"
    exit 1
  fi
  if ! grep -qiE 'invariant .* violated|outcome is: Error' "$dir/out.log"; then
    echo "$model bite FAILED: mutant erred for the wrong reason (not an invariant violation)" >&2
    cat "$dir/out.log" >&2
    rm -rf "$dir"
    exit 1
  fi
  rm -rf "$dir"
  echo "$model bite OK ($expect_inv guard is load-bearing)"
}
marker_bite LogChainIntegrity 'THE FENCE'           NoStaleWrite
marker_bite LogChainIntegrity 'THE COMPARE-AND-SET' NoBlindWrite

# --- DR-0066 §4 publish-order bites (models/tla/SubstratePublishOrder.tla) -------
# One bite per ordering edge, and they must violate different invariants: the
# claim is that publishing bottom-up is three separate obligations, not one
# restated three ways.
marker_bite SubstratePublishOrder 'CONTENT BEFORE HISTORY'          NoHistoryWithoutContent
marker_bite SubstratePublishOrder 'HISTORY BEFORE REF'              NoRefWithoutItsHistory
marker_bite SubstratePublishOrder 'NO REF STRONGER THAN ITS CLOSURE' NoRefStrongerThanItsClosure

# --- DR-0068 pinned-resolution bites (models/tla/PinnedResolution.tla) -----------
# Three guards, three invariants, and they must be independent for the same
# reason the log-chain pair must be. Two of these are SUBSTITUTIONS rather than
# deletions, because removing the line would leave a variable unassigned and
# Apalache would fail to parse — a parse failure is not the invariant doing its
# job (the lesson the custody bites paid for below).
#
# Every mutant is compared against the original before it is checked. A sed
# expression that silently matches nothing would otherwise produce an unmutated
# model that passes, and the bite would report success having tested nothing.
pinned_bite() {
  local label="$1" expr="$2" expect_inv="$3"
  local dir
  dir="$(mktemp -d)"
  sed "$expr" "$ROOT/models/tla/PinnedResolution.tla" > "$dir/PinnedResolution.tla"
  if cmp -s "$dir/PinnedResolution.tla" "$ROOT/models/tla/PinnedResolution.tla"; then
    echo "pinned-resolution bite FAILED: '$label' changed nothing, so it tested nothing" >&2
    rm -rf "$dir"
    exit 1
  fi
  echo "== pinned-resolution bite: $label must violate $expect_inv"
  if "${APALACHE[@]}" check --cinit=ConstInit --init=Init --next=Next \
        --inv=SafetyInvariants --length=6 "$dir/PinnedResolution.tla" \
        > "$dir/out.log" 2>&1; then
    echo "pinned-resolution bite FAILED: '$label' did not violate $expect_inv" >&2
    rm -rf "$dir"
    exit 1
  fi
  if ! grep -qiE 'invariant .* violated|outcome is: Error' "$dir/out.log"; then
    echo "pinned-resolution bite FAILED: '$label' erred for the wrong reason" >&2
    cat "$dir/out.log" >&2
    rm -rf "$dir"
    exit 1
  fi
  rm -rf "$dir"
  echo "pinned-resolution bite OK ($expect_inv guard is load-bearing)"
}
# A runner that resolves the ref itself instead of taking the trigger's cut.
pinned_bite 'resolve from the ref' 's/= triggerCut\]/= ref]/' RunnersFiredTogetherAgree
# The pin taken later than dispatch, leaving a window between a cut being named
# and being held. This is the gap the model found in the first place.
pinned_bite 'no pin at dispatch' 's/pinned \\cup {ref}/pinned/' NamedCutIsPinned
# A collector that ignores run pins.
pinned_bite 'collector ignores pins' '/COLLECT ONLY UNPINNED/d' NoPinnedCutCollected

# --- DR-0053 credential custody bites (models/tla/CredentialCustody.tla) ---------
# Every safety invariant in the custody model must have its OWN bite: the seven
# mutations below violate invariants 2..8 respectively, so no invariant is
# riding on another's teeth. Length 7, because a use is split into
# StartUse/CompleteUse and the interesting traces (revoke or reseal landing
# mid-flight) need the extra step.
#
# Two mutations must be scoped to CompleteUse by name rather than matched on
# text: `c \notin revoked` and the rung guard BOTH appear in StartUse too, and
# removing the StartUse copy proves nothing -- the claim is specifically that
# these are RE-EVALUATED at completion.
#
# custody_bite_in matches LITERALLY, and passes its strings through the
# environment rather than through awk's `-v`. Both halves of that matter, and
# the reason is a bug this check shipped with.
#
# `-v` unescapes its value once, and the awks disagree about what to do with an
# escape they do not know. mawk leaves `\[` alone; gawk rewrites it to `[` and
# warns. So `sealedAt\[c\] >= MinRung` stayed a literal on a developer's mawk
# and became the character class `[c]` on the runner's gawk, and the anchor
# `^CompleteUse\(c\) ==` became the group `(c)`. Neither matched there, `b` was
# never set, and NO mutation was produced at all -- every scoped bite silently
# tested nothing while reporting the file unchanged. The mirror caught it only
# because `custody_run` checks that a MUTANT line exists.
#
# Replacements were exposed to the same rule, in the direction that is worse: a
# replacement written `  \* MUTANT: ...` reaches gawk as `  * MUTANT: ...`,
# which is not a TLA comment. That mutant fails to parse, and a parse failure is
# not the invariant doing its job.
#
# ENVIRON values are not escape-processed by any awk, and index() has no
# metacharacters, so patterns are now written exactly as they appear in the
# spec and mean exactly that.
CUSTODY_MODEL="$ROOT/models/tla/CredentialCustody.tla"

custody_run() {
  local dir="$1" what="$2"
  if ! grep -q 'MUTANT' "$dir/CredentialCustody.tla"; then
    echo "custody bite FAILED: mutation for $what matched nothing (the spec moved under it)" >&2
    rm -rf "$dir"; exit 1
  fi
  echo "== custody bite: $what mutant must be caught"
  if "${APALACHE[@]}" check --cinit=ConstInit --init=Init --next=Next \
        --inv=SafetyInvariants --length=7 "$dir/CredentialCustody.tla" > "$dir/out.log" 2>&1; then
    echo "custody bite FAILED: mutant did not violate $what" >&2
    rm -rf "$dir"; exit 1
  fi
  if ! grep -qiE 'invariant .* violated|outcome is: Error' "$dir/out.log"; then
    echo "custody bite FAILED: $what mutant erred for the wrong reason (not an invariant violation)" >&2
    cat "$dir/out.log" >&2
    rm -rf "$dir"; exit 1
  fi
  rm -rf "$dir"
  echo "custody bite OK ($what is load-bearing)"
}

# Whole-file textual mutation.
custody_bite() {
  local sed_script="$1" what="$2" dir
  dir="$(mktemp -d)"
  sed "$sed_script" "$CUSTODY_MODEL" > "$dir/CredentialCustody.tla"
  custody_run "$dir" "$what"
}

# Mutation scoped to the first matching line inside a named action.
custody_bite_in() {
  local action="$1" pattern="$2" replacement="$3" what="$4" dir
  dir="$(mktemp -d)"
  CB_ACT="${action}(c) ==" CB_PAT="$pattern" CB_REP="$replacement" \
  awk 'BEGIN { act = ENVIRON["CB_ACT"]; pat = ENVIRON["CB_PAT"]; rep = ENVIRON["CB_REP"] }
       index($0, act) == 1 { b = 1 }
       b && index($0, pat) { print rep; b = 0; next }
       { print }' \
    "$CUSTODY_MODEL" > "$dir/CredentialCustody.tla"
  custody_run "$dir" "$what"
}

custody_bite 's|^SubstitutionPrincipal == "custodian"$|SubstitutionPrincipal == "whip" \\* MUTANT: direct-fetch fallback|' NoPlaintextInWhip
custody_bite_in CompleteUse 'sealedAt[c] >= MinRung' '  \* MUTANT: completion-time rung check removed' RungFloor
custody_bite 's|^  /\\ leased. = leased \\ {c}$|  /\\ UNCHANGED leased \\* MUTANT: revocation keeps the lease|' NoUseAfterRevoke
custody_bite_in CompleteUse 'c \notin revoked' '  \* MUTANT: mid-flight revocation check removed' NoCompletionAfterRevoke
custody_bite_in CompleteUse "admitted' = admitted" '  /\ UNCHANGED admitted \* MUTANT: use not recorded' UsesAreRecorded
custody_bite 's|^  /\\ Cardinality(versions\[c\]) > 1$|  \\* MUTANT: overlap guard removed|' RotationNeverEmpty
custody_bite 's|^  /\\ uses\[c\] < Budget$|  \\* MUTANT: budget guard removed|' BudgetRespected
