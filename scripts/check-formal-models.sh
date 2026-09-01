#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v maude >/dev/null 2>&1; then
  echo "maude not found; skipping Maude checks" >&2
  exit 1
fi

# Ordered per-search verdict signature for a test file (S=Solution, N=No solution),
# in search order. Catches a swapped Solution/No-solution PAIR that leaves the
# aggregate counts unchanged. The maude runs below do NOT read the platform catalog
# (WHIPPLESCRIPT_PLATFORM_CATALOG_PATH is unset when the loop runs `maude`), so this
# signature is reproducible without the catalog / a workspace build.
VERDICTS_FILE="$ROOT/models/maude/tests/expected-verdicts.tsv"

verdict_signature() {
  grep -oE '^Solution 1|^No solution\.' \
    | sed 's/Solution 1/S/; s/No solution\./N/' \
    | paste -sd '' -
}

# `check-formal-models.sh --update-verdicts` regenerates the signature golden. Needs
# only maude (no cargo/store), so it works even mid-refactor elsewhere in the tree.
if [[ "${1:-}" == "--update-verdicts" ]]; then
  {
    echo "# Ordered per-search verdict signature for each Maude test (S=Solution, N=No solution),"
    echo "# in search order. check-formal-models.sh asserts each file's actual signature matches;"
    echo "# this catches a swapped Solution/No-solution PAIR that leaves the aggregate counts equal."
    echo "# Regenerate with: scripts/check-formal-models.sh --update-verdicts"
    echo "# filename<TAB>signature"
  } > "$VERDICTS_FILE"
  for test_file in "$ROOT"/models/maude/tests/*.maude; do
    name="$(basename "$test_file")"
    sig="$(maude "$test_file" 2>/dev/null | verdict_signature)"
    printf '%s\t%s\n' "$name" "$sig" >> "$VERDICTS_FILE"
  done
  echo "wrote $VERDICTS_FILE"
  exit 0
fi

declare -A EXPECTED_SIGNATURE=()
while IFS=$'\t' read -r vname vsig; do
  [[ -z "$vname" || "$vname" == \#* ]] && continue
  EXPECTED_SIGNATURE["$vname"]="$vsig"
done < "$VERDICTS_FILE"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
PLATFORM_CATALOG_PATH="$TMP_DIR/platform-construct-catalog.json"

(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- package catalog \
    > "$PLATFORM_CATALOG_PATH"
)
unset WHIPPLESCRIPT_PLATFORM_CATALOG_PATH

validate_model_search_report() {
  python3 "$ROOT/scripts/validate-model-search-report.py" \
    --root "$ROOT" \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    "$@"
}

python3 - "$ROOT" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
module_path = root / "scripts" / "lowered-ir-to-maude.py"
spec = importlib.util.spec_from_file_location("lowered_ir_to_maude_bridge", module_path)
if spec is None or spec.loader is None:
    raise SystemExit(f"could not load {module_path}")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

edges = {
    bridge.edge_ref("required:memory", "provided:alpha"): {
        "required_port_id": "required:memory",
        "provided_port_id": "provided:alpha",
        "provider_node_id": "provider:alpha",
    },
    bridge.edge_ref("required:memory", "provided:beta"): {
        "required_port_id": "required:memory",
        "provided_port_id": "provided:beta",
        "provider_node_id": "provider:beta",
    },
}
edge = bridge.edge_for_lowering(edges, "required:memory", "provided:alpha")
if edge["provider_node_id"] != "provider:alpha":
    raise SystemExit("lowered IR bridge did not resolve edge by full edge ref")
try:
    bridge.edge_for_lowering(edges, "required:memory", "provided:missing")
except SystemExit as exc:
    if "unknown edge lowering ref" not in str(exc):
        raise
else:
    raise SystemExit("lowered IR bridge accepted an unknown edge lowering ref")
PY

declare -A EXPECTED_NO_SOLUTION=(
  ["trace-lifecycle-conformance.maude"]=3
  ["action-expansion.maude"]=3
  ["effect-key.maude"]=4
  ["telemetry-cursor.maude"]=1
  ["merge-slice.maude"]=4
  ["alpha-canonicalization.maude"]=4
  ["merge-confluence.maude"]=4
  ["text-merge-compose.maude"]=4
  ["workstream.maude"]=5
  ["workstream-boundary.maude"]=12
  ["branch-effect-key.maude"]=2
  ["selective-undo.maude"]=2
  ["repair-containment.maude"]=4
  ["op-undo.maude"]=2
  ["resolution-memory.maude"]=2
  ["chat-fork.maude"]=2
  ["turn-witness.maude"]=2
  ["seam-crossing.maude"]=2
  ["stat-cache.maude"]=3
  ["improve-acceptance.maude"]=4
  ["improve-holdout.maude"]=3
  ["improve-precedent.maude"]=4
  ["prefix-replay.maude"]=2
  ["settle-stopping.maude"]=2
  ["contradiction-reopener.maude"]=2
  ["pattern-recursion.maude"]=2
  ["effect-cycle-pacing.maude"]=9
  ["termination-measure.maude"]=9
  ["duration-arithmetic.maude"]=2
  ["rule-autofail.maude"]=5
  ["pinned-progressions.maude"]=5
  ["view-derivation.maude"]=5
  ["view-retraction.maude"]=2
  ["settled-firing-closure.maude"]=3
  ["revision-rule-correspondence.maude"]=5
  ["std-construct-authorization.maude"]=7
  ["messaging-capability-report.maude"]=4
  ["script-capability-seeding.maude"]=2
  ["script-hard-off.maude"]=5
  ["turn-access-grant.maude"]=2
  ["admission.maude"]=11
  ["clock-source.maude"]=4
  ["coerce-branches.maude"]=1
  ["construct-graph.maude"]=21
  ["construct-grammar.maude"]=19
  ["construct-interop-examples.maude"]=7
  ["lowering-class-lifecycle.maude"]=15
  ["construct-lowering.maude"]=18
  ["lowering-runtime-handoff.maude"]=13
  ["tracker-claim-turn.maude"]=2
  ["flow-classification.maude"]=3
  ["tracker-lease.maude"]=4
  ["tracker-merge.maude"]=3
  ["ledger-freshness.maude"]=5
  ["tracker-lease-merge.maude"]=2
  ["tracker-readiness.maude"]=4
  ["tracker-projection.maude"]=3
  ["package-contract.maude"]=16
  ["effect-dependencies.maude"]=2
  ["guard-commit-bite.maude"]=2
  ["expression-kernel.maude"]=15
  ["native-provider-lifecycle.maude"]=2
  ["owned-harness-loop.maude"]=5
  ["owned-harness-envelope.maude"]=3
  ["owned-harness-sandbox.maude"]=1
  ["owned-harness-tracker.maude"]=2
  ["owned-harness-compaction.maude"]=1
  ["owned-harness-resume.maude"]=1
  ["mcp-admission.maude"]=6
  ["model-visible-world.maude"]=5
  ["cache-prefix-append-only.maude"]=1
  ["compaction-record-once.maude"]=1
  ["compaction-epoch-lifecycle.maude"]=2
  ["harness-class.maude"]=2
  ["harness-evidence-fork.maude"]=2
  ["delegated-settings-authority.maude"]=2
  ["delegated-wire-lifecycle.maude"]=3
  ["compute-result-cache.maude"]=2
  ["compute-priority-queue.maude"]=2
  ["restorable-context.maude"]=4
  ["restore-replay.maude"]=2
  ["skills-never-grant.maude"]=2
  ["catalogue-determinism.maude"]=1
  ["provenance-completeness.maude"]=1
  ["subworkflow-convergence.maude"]=3
  ["subworkflow-lease.maude"]=1
  ["subworkflow-attestation.maude"]=2
  ["infoflow-integrity.maude"]=4
  ["infoflow-confidentiality.maude"]=4
  ["infoflow-reader-sets.maude"]=4
  ["infoflow-redaction.maude"]=3
  ["infoflow-redact-provenance.maude"]=2
  ["infoflow-field-signature.maude"]=6
  ["infoflow-input-provenance.maude"]=3
  ["infoflow-fact-provenance.maude"]=2
  ["infoflow-output-integrity.maude"]=3
  ["infoflow-signal-carriage.maude"]=5
  ["infoflow-coord-carriage.maude"]=4
  ["infoflow-tracker-carriage.maude"]=4
  ["infoflow-composition.maude"]=9
  ["infoflow-package.maude"]=2
  ["infoflow-carriage.maude"]=2
  ["infoflow-signature.maude"]=6
  ["infoflow-staging.maude"]=2
  ["infoflow-declassifier.maude"]=5
  ["envelope-composition.maude"]=14
  ["envelope-minting.maude"]=6
  ["actsfor-unanimity.maude"]=2
  ["credential-no-eliminator.maude"]=9
  ["credential-verify-endorse.maude"]=6
  ["credential-rung-evidence.maude"]=6
  ["credential-wrap-carriage.maude"]=5
  ["credential-unwrap-confinement.maude"]=7
  ["credential-region-escape.maude"]=4
  ["credential-region-materialization.maude"]=6
  ["credential-scope-narrowing.maude"]=4
  ["agent-provider-binding.maude"]=3
  ["model-trust-admissibility.maude"]=6
  ["case-family.maude"]=4
  ["case-selector.maude"]=2
  ["discriminant-schema.maude"]=3
  ["milestone-signal.maude"]=3
  ["effect-error.maude"]=4
  ["policy-capacity-retry.maude"]=2
  ["external-event-loop.maude"]=1
  ["workflow-composition.maude"]=5
  ["workflow-revision.maude"]=5
  ["workflow-scoping.maude"]=3
  ["workflow-authority-attenuation.maude"]=3
  ["workflow-runtime-marker-reresolution.maude"]=3
  ["terminal-payload-shape.maude"]=2
  ["invoke-result-typing.maude"]=3
  ["pattern-body-surface.maude"]=2
)

declare -A EXPECTED_SOLUTION=(
  ["trace-lifecycle-conformance.maude"]=10
  ["action-expansion.maude"]=2
  ["effect-key.maude"]=4
  ["telemetry-cursor.maude"]=5
  ["merge-slice.maude"]=6
  ["alpha-canonicalization.maude"]=8
  ["merge-confluence.maude"]=2
  ["text-merge-compose.maude"]=7
  ["workstream.maude"]=3
  ["workstream-boundary.maude"]=12
  ["branch-effect-key.maude"]=4
  ["selective-undo.maude"]=3
  ["repair-containment.maude"]=6
  ["op-undo.maude"]=4
  ["resolution-memory.maude"]=3
  ["chat-fork.maude"]=5
  ["turn-witness.maude"]=4
  ["seam-crossing.maude"]=4
  ["stat-cache.maude"]=5
  ["improve-acceptance.maude"]=4
  ["improve-holdout.maude"]=5
  ["improve-precedent.maude"]=3
  ["prefix-replay.maude"]=3
  ["settle-stopping.maude"]=3
  ["contradiction-reopener.maude"]=3
  ["pattern-recursion.maude"]=3
  ["effect-cycle-pacing.maude"]=5
  ["termination-measure.maude"]=5
  ["duration-arithmetic.maude"]=2
  ["rule-autofail.maude"]=4
  ["pinned-progressions.maude"]=7
  ["view-derivation.maude"]=8
  ["view-retraction.maude"]=4
  ["settled-firing-closure.maude"]=4
  ["revision-rule-correspondence.maude"]=7
  ["std-construct-authorization.maude"]=5
  ["messaging-capability-report.maude"]=4
  ["script-capability-seeding.maude"]=1
  ["script-hard-off.maude"]=3
  ["turn-access-grant.maude"]=2
  ["admission.maude"]=8
  ["clock-source.maude"]=5
  ["coerce-branches.maude"]=3
  ["construct-graph.maude"]=11
  ["construct-grammar.maude"]=15
  ["construct-interop-examples.maude"]=7
  ["lowering-class-lifecycle.maude"]=11
  ["construct-lowering.maude"]=12
  ["lowering-runtime-handoff.maude"]=5
  ["tracker-claim-turn.maude"]=2
  ["flow-classification.maude"]=5
  ["tracker-lease.maude"]=5
  ["tracker-merge.maude"]=6
  ["ledger-freshness.maude"]=7
  ["tracker-lease-merge.maude"]=4
  ["tracker-readiness.maude"]=3
  ["tracker-projection.maude"]=2
  ["package-contract.maude"]=10
  ["effect-dependencies.maude"]=4
  ["guard-commit-bite.maude"]=2
  ["expression-kernel.maude"]=19
  ["native-provider-lifecycle.maude"]=3
  ["owned-harness-loop.maude"]=3
  ["owned-harness-envelope.maude"]=2
  ["owned-harness-sandbox.maude"]=1
  ["owned-harness-tracker.maude"]=2
  ["owned-harness-compaction.maude"]=1
  ["owned-harness-resume.maude"]=1
  ["mcp-admission.maude"]=6
  ["model-visible-world.maude"]=11
  ["cache-prefix-append-only.maude"]=3
  ["compaction-record-once.maude"]=2
  ["compaction-epoch-lifecycle.maude"]=3
  ["harness-class.maude"]=2
  ["harness-evidence-fork.maude"]=2
  ["delegated-settings-authority.maude"]=2
  ["delegated-wire-lifecycle.maude"]=3
  ["compute-result-cache.maude"]=3
  ["compute-priority-queue.maude"]=3
  ["restorable-context.maude"]=3
  ["restore-replay.maude"]=2
  ["skills-never-grant.maude"]=2
  ["catalogue-determinism.maude"]=2
  ["provenance-completeness.maude"]=2
  ["subworkflow-convergence.maude"]=4
  ["subworkflow-lease.maude"]=3
  ["subworkflow-attestation.maude"]=3
  ["infoflow-integrity.maude"]=4
  ["infoflow-confidentiality.maude"]=4
  ["infoflow-reader-sets.maude"]=4
  ["infoflow-redaction.maude"]=2
  ["infoflow-redact-provenance.maude"]=2
  ["infoflow-field-signature.maude"]=6
  ["infoflow-input-provenance.maude"]=3
  ["infoflow-fact-provenance.maude"]=4
  ["infoflow-output-integrity.maude"]=3
  ["infoflow-signal-carriage.maude"]=4
  ["infoflow-coord-carriage.maude"]=4
  ["infoflow-tracker-carriage.maude"]=5
  ["infoflow-composition.maude"]=9
  ["infoflow-package.maude"]=3
  ["infoflow-carriage.maude"]=2
  ["infoflow-signature.maude"]=3
  ["infoflow-staging.maude"]=2
  ["infoflow-declassifier.maude"]=3
  ["envelope-composition.maude"]=18
  ["envelope-minting.maude"]=8
  ["actsfor-unanimity.maude"]=3
  ["credential-no-eliminator.maude"]=8
  ["credential-verify-endorse.maude"]=4
  ["credential-rung-evidence.maude"]=5
  ["credential-wrap-carriage.maude"]=4
  ["credential-unwrap-confinement.maude"]=6
  ["credential-region-escape.maude"]=5
  ["credential-region-materialization.maude"]=5
  ["credential-scope-narrowing.maude"]=5
  ["agent-provider-binding.maude"]=5
  ["model-trust-admissibility.maude"]=5
  ["case-family.maude"]=5
  ["case-selector.maude"]=1
  ["discriminant-schema.maude"]=5
  ["milestone-signal.maude"]=2
  ["effect-error.maude"]=5
  ["policy-capacity-retry.maude"]=4
  ["external-event-loop.maude"]=2
  ["workflow-composition.maude"]=7
  ["workflow-revision.maude"]=4
  ["workflow-scoping.maude"]=6
  ["workflow-authority-attenuation.maude"]=3
  ["workflow-runtime-marker-reresolution.maude"]=3
  ["terminal-payload-shape.maude"]=6
  ["invoke-result-typing.maude"]=7
  ["pattern-body-surface.maude"]=6
)

declare -A SEEN_TEST=()

for test_file in "$ROOT"/models/maude/tests/*.maude; do
  echo "== maude ${test_file#"$ROOT"/}"
  output="$(maude "$test_file")"
  printf '%s\n' "$output"

  test_name="$(basename "$test_file")"
  SEEN_TEST["$test_name"]=1
  actual_no_solution="$(grep -c 'No solution\.' <<<"$output" || true)"
  actual_solution="$(grep -c '^Solution 1' <<<"$output" || true)"

  if [[ "${EXPECTED_NO_SOLUTION[$test_name]:-}" != "$actual_no_solution" ]]; then
    echo "unexpected No solution count for $test_name: got $actual_no_solution, expected ${EXPECTED_NO_SOLUTION[$test_name]:-unset}" >&2
    exit 1
  fi

  if [[ "${EXPECTED_SOLUTION[$test_name]:-}" != "$actual_solution" ]]; then
    echo "unexpected Solution 1 count for $test_name: got $actual_solution, expected ${EXPECTED_SOLUTION[$test_name]:-unset}" >&2
    exit 1
  fi

  # Identity, not just totals: the ordered verdict signature must match. This is what
  # catches a swapped Solution/No-solution pair (which keeps the counts balanced).
  actual_signature="$(verdict_signature <<<"$output")"
  if [[ -z "${EXPECTED_SIGNATURE[$test_name]+set}" ]]; then
    echo "no expected verdict signature for $test_name (run scripts/check-formal-models.sh --update-verdicts)" >&2
    exit 1
  fi
  if [[ "${EXPECTED_SIGNATURE[$test_name]}" != "$actual_signature" ]]; then
    echo "verdict signature mismatch for $test_name: got '$actual_signature', expected '${EXPECTED_SIGNATURE[$test_name]}'" >&2
    exit 1
  fi
done

for test_name in "${!EXPECTED_NO_SOLUTION[@]}"; do
  if [[ -z "${SEEN_TEST[$test_name]:-}" ]]; then
    echo "expected No solution count for missing Maude test: $test_name" >&2
    exit 1
  fi
done

for test_name in "${!EXPECTED_SOLUTION[@]}"; do
  if [[ -z "${SEEN_TEST[$test_name]:-}" ]]; then
    echo "expected Solution 1 count for missing Maude test: $test_name" >&2
    exit 1
  fi
done

echo "== generated Maude from platform construct catalog"
(
  cd "$ROOT"
  python3 - "$PLATFORM_CATALOG_PATH" > "$TMP_DIR/generated-platform-catalog-expected.txt" <<'PY'
import json
import sys

catalog = json.load(open(sys.argv[1]))
print(len(catalog["lowerings"]))
PY
  python3 scripts/platform-catalog-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    > "$TMP_DIR/generated-platform-catalog.maude"
  output="$(maude "$TMP_DIR/generated-platform-catalog.maude")"
  printf '%s\n' "$output"
  expected_solution="$(cat "$TMP_DIR/generated-platform-catalog-expected.txt")"
  actual_solution="$(grep -c '^Solution 1' <<<"$output" || true)"
  actual_no_solution="$(grep -c 'No solution\.' <<<"$output" || true)"
  actual_warnings="$(grep -c '^Warning:' <<<"$output" || true)"
  if [[ "$actual_solution" != "$expected_solution" ]]; then
    echo "unexpected generated platform-catalog Solution 1 count: got $actual_solution, expected $expected_solution" >&2
    exit 1
  fi
  if [[ "$actual_no_solution" != 0 ]]; then
    echo "unexpected generated platform-catalog No solution count: got $actual_no_solution" >&2
    exit 1
  fi
  if [[ "$actual_warnings" != 0 ]]; then
    echo "generated platform-catalog Maude emitted warnings" >&2
    exit 1
  fi
)

echo "== generated Maude from package contract"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- package check --json \
    std/manifests/memory.json \
    > "$TMP_DIR/generated-package-check.json"
  python3 - "$TMP_DIR/generated-package-check.json" > "$TMP_DIR/generated-package-contract-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
registry = report["package_contract"]["contract_registry"]
print(2 * (len(registry["effect_contracts"]) + len(registry["constructs"])))
PY
  python3 scripts/package-contract-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-package-check.json" \
    > "$TMP_DIR/generated-package-contract.maude"
  output="$(maude "$TMP_DIR/generated-package-contract.maude")"
  printf '%s\n' "$output"
  expected_solution="$(cat "$TMP_DIR/generated-package-contract-expected.txt")"
  actual_solution="$(grep -c '^Solution 1' <<<"$output" || true)"
  actual_no_solution="$(grep -c 'No solution\.' <<<"$output" || true)"
  actual_warnings="$(grep -c '^Warning:' <<<"$output" || true)"
  if [[ "$actual_solution" != "$expected_solution" ]]; then
    echo "unexpected generated package-contract Solution 1 count: got $actual_solution, expected $expected_solution" >&2
    exit 1
  fi
  if [[ "$actual_no_solution" != 0 ]]; then
    echo "unexpected generated package-contract No solution count: got $actual_no_solution" >&2
    exit 1
  fi
  if [[ "$actual_warnings" != 0 ]]; then
    echo "generated package-contract Maude emitted warnings" >&2
    exit 1
  fi
  python3 - "$TMP_DIR/generated-package-check.json" > "$TMP_DIR/generated-package-construct-grammar-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
registry = report["package_contract"]["contract_registry"]
print(2 * len(registry["constructs"]))
PY
  python3 scripts/package-construct-grammar-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-package-check.json" \
    > "$TMP_DIR/generated-package-construct-grammar.maude"
  output="$(maude "$TMP_DIR/generated-package-construct-grammar.maude")"
  printf '%s\n' "$output"
  expected_solution="$(cat "$TMP_DIR/generated-package-construct-grammar-expected.txt")"
  actual_solution="$(grep -c '^Solution 1' <<<"$output" || true)"
  actual_no_solution="$(grep -c 'No solution\.' <<<"$output" || true)"
  actual_warnings="$(grep -c '^Warning:' <<<"$output" || true)"
  if [[ "$actual_solution" != "$expected_solution" ]]; then
    echo "unexpected generated package construct-grammar Solution 1 count: got $actual_solution, expected $expected_solution" >&2
    exit 1
  fi
  if [[ "$actual_no_solution" != 0 ]]; then
    echo "unexpected generated package construct-grammar No solution count: got $actual_no_solution" >&2
    exit 1
  fi
  if [[ "$actual_warnings" != 0 ]]; then
    echo "generated package construct-grammar Maude emitted warnings" >&2
    exit 1
  fi
  python3 - "$TMP_DIR/generated-package-check.json" "$TMP_DIR/generated-package-check-stale-contract.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
report["package_contract"]["package_contract_digest"] = "0" * 64
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/package-contract-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-package-check-stale-contract.json" \
    > "$TMP_DIR/generated-package-check-stale-contract.maude" \
    2> "$TMP_DIR/generated-package-check-stale-contract.err"; then
    echo "expected package-contract bridge to reject stale package contract digest" >&2
    exit 1
  fi
  grep -q 'package_contract.package_contract_digest does not match body' \
    "$TMP_DIR/generated-package-check-stale-contract.err"
)

echo "== generated Maude from check-report construct graph"
(
  cd "$ROOT"
  # Lock flow (third-party supply chain): std packages ship embedded and can
  # never be lock-provided, so lock mechanics are exercised via the vendor
  # `notes` package. Portable locks record source.path relative to the lock
  # directory, so the manifest must live under that directory.
  cp examples/packages/notes.json "$TMP_DIR/notes.json"
  cargo run --quiet -p whipplescript -- package lock --output "$TMP_DIR/package-lock.json" \
    "$TMP_DIR/notes.json" >/dev/null
  cargo run --quiet -p whipplescript -- check \
    --package-lock "$TMP_DIR/package-lock.json" \
    examples/package-notes.whip >/dev/null
  # The construct-graph source itself: package-memory.whip resolves its
  # `std.memory` import from the embedded manifest — no lock needed.
  cargo run --quiet -p whipplescript -- --json check \
    examples/package-memory.whip \
    > "$TMP_DIR/generated-construct-graph-check.json"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" > "$TMP_DIR/generated-construct-graph-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
graph = report[0]["construct_graph"]
print(len(graph["nodes"]) + len(graph["edges"]) + 2)
PY
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-multi-entry.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
if len(report) != 1:
    raise SystemExit(f"expected one source report entry, got {len(report)}")
json.dump([report[0], report[0]], open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-multi-entry.json" \
    > "$TMP_DIR/generated-construct-graph-multi-entry.maude" \
    2> "$TMP_DIR/generated-construct-graph-multi-entry.err"; then
    echo "expected construct graph bridge to reject ambiguous multi-entry check reports" >&2
    exit 1
  fi
  grep -q 'pass --entry-index to select the artifact to lower' \
    "$TMP_DIR/generated-construct-graph-multi-entry.err"
  python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    --entry-index 1 \
    "$TMP_DIR/generated-construct-graph-multi-entry.json" \
    > "$TMP_DIR/generated-construct-graph-multi-entry-selected.maude"
  grep -q 'WHIPPLESCRIPT-GENERATED-CONSTRUCT-GRAPH' \
    "$TMP_DIR/generated-construct-graph-multi-entry-selected.maude"
  cargo run --quiet -p whipplescript -- verify-report --emit construct-graph \
    "$TMP_DIR/generated-construct-graph-check.json" \
    > "$TMP_DIR/generated-construct-graph-verified.json"
  python3 - "$TMP_DIR/generated-construct-graph-verified.json" "$TMP_DIR/generated-construct-graph-verified-multi-entry.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
bundle = json.load(open(source_path))
entries = bundle.get("entries")
if not isinstance(entries, list) or len(entries) != 1:
    raise SystemExit(f"expected one verified artifact entry, got {entries!r}")
bundle["entries"] = [entries[0], entries[0]]
json.dump(bundle, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-verified-multi-entry.json" \
    > "$TMP_DIR/generated-construct-graph-verified-multi-entry.maude" \
    2> "$TMP_DIR/generated-construct-graph-verified-multi-entry.err"; then
    echo "expected construct graph bridge to reject ambiguous multi-entry verified bundles" >&2
    exit 1
  fi
  grep -q 'pass --entry-index to select the artifact to lower' \
    "$TMP_DIR/generated-construct-graph-verified-multi-entry.err"
  python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    --entry-index 1 \
    "$TMP_DIR/generated-construct-graph-verified-multi-entry.json" \
    > "$TMP_DIR/generated-construct-graph-verified-multi-entry-selected.maude"
  grep -q 'WHIPPLESCRIPT-GENERATED-CONSTRUCT-GRAPH' \
    "$TMP_DIR/generated-construct-graph-verified-multi-entry-selected.maude"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-invalid-schema.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
nodes = report[0]["construct_graph"]["nodes"]
if not nodes:
    raise SystemExit("missing construct graph node to invalidate")
del nodes[0]["node_id"]
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-invalid-schema.json" \
    > "$TMP_DIR/generated-construct-graph-invalid-schema.maude" \
    2> "$TMP_DIR/generated-construct-graph-invalid-schema.err"; then
    echo "expected construct graph bridge to reject schema-invalid graph input" >&2
    exit 1
  fi
  grep -q 'construct graph failed schema validation against construct_graph_v0.schema.json' \
    "$TMP_DIR/generated-construct-graph-invalid-schema.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-missing-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
facts = report[0]["construct_graph"]["derived_facts"]
report[0]["construct_graph"]["derived_facts"] = [
    fact
    for fact in facts
    if not str(fact.get("predicate", "")).startswith("validator.graph.accepted:")
]
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-missing-trace.json" \
    > "$TMP_DIR/generated-construct-graph-missing-trace.maude" \
    2> "$TMP_DIR/generated-construct-graph-missing-trace.err"; then
    echo "expected construct graph bridge to reject missing validator trace" >&2
    exit 1
  fi
  grep -q 'derived_facts missing validator predicate' \
    "$TMP_DIR/generated-construct-graph-missing-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-spoofed-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for fact in report[0]["construct_graph"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("validator.graph.accepted:"):
        fact["owner_subsystem"] = "compiler"
        break
else:
    raise SystemExit("missing construct graph acceptance fact to spoof")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-spoofed-trace.json" \
    > "$TMP_DIR/generated-construct-graph-spoofed-trace.maude" \
    2> "$TMP_DIR/generated-construct-graph-spoofed-trace.err"; then
    echo "expected construct graph bridge to reject spoofed validator trace owner" >&2
    exit 1
  fi
  grep -q 'derived_facts missing validator predicate' \
    "$TMP_DIR/generated-construct-graph-spoofed-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-missing-node-profile-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
facts = report[0]["construct_graph"]["derived_facts"]
report[0]["construct_graph"]["derived_facts"] = [
    fact
    for fact in facts
    if not str(fact.get("predicate", "")).startswith("validator.node.profile:")
]
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-missing-node-profile-trace.json" \
    > "$TMP_DIR/generated-construct-graph-missing-node-profile-trace.maude" \
    2> "$TMP_DIR/generated-construct-graph-missing-node-profile-trace.err"; then
    echo "expected construct graph bridge to reject missing node profile validator trace" >&2
    exit 1
  fi
  grep -q 'derived_facts missing validator predicate' \
    "$TMP_DIR/generated-construct-graph-missing-node-profile-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-incomplete-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
graph_id = report[0]["construct_graph"]["graph_id"]
for fact in report[0]["construct_graph"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("validator.graph.accepted:"):
        fact["input_refs"] = [
            ref for ref in fact.get("input_refs", []) if ref != graph_id
        ]
        break
else:
    raise SystemExit("missing construct graph acceptance fact to weaken")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-incomplete-trace.json" \
    > "$TMP_DIR/generated-construct-graph-incomplete-trace.maude" \
    2> "$TMP_DIR/generated-construct-graph-incomplete-trace.err"; then
    echo "expected construct graph bridge to reject incomplete validator trace input refs" >&2
    exit 1
  fi
  grep -q 'validator predicate input_refs incomplete' \
    "$TMP_DIR/generated-construct-graph-incomplete-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-duplicate-trace.json" <<'PY'
import copy
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
facts = report[0]["construct_graph"]["derived_facts"]
for fact in facts:
    if str(fact.get("predicate", "")).startswith("validator.graph.accepted:"):
        duplicate = copy.deepcopy(fact)
        duplicate.setdefault("diagnostic_span", {})["construct"] = (
            "semantic-duplicate-validator-predicate"
        )
        facts.append(duplicate)
        break
else:
    raise SystemExit("missing construct graph acceptance fact to duplicate")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-duplicate-trace.json" \
    > "$TMP_DIR/generated-construct-graph-duplicate-trace.maude" \
    2> "$TMP_DIR/generated-construct-graph-duplicate-trace.err"; then
    echo "expected construct graph bridge to reject duplicate validator trace" >&2
    exit 1
  fi
  grep -q 'duplicate validator predicate' \
    "$TMP_DIR/generated-construct-graph-duplicate-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-extra-trace-ref.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for fact in report[0]["construct_graph"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("validator.graph.accepted:"):
        fact.setdefault("input_refs", []).append("bogus:trace-ref")
        break
else:
    raise SystemExit("missing construct graph acceptance fact to pad")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-extra-trace-ref.json" \
    > "$TMP_DIR/generated-construct-graph-extra-trace-ref.maude" \
    2> "$TMP_DIR/generated-construct-graph-extra-trace-ref.err"; then
    echo "expected construct graph bridge to reject padded validator trace refs" >&2
    exit 1
  fi
  grep -q 'validator predicate input_refs unexpected' \
    "$TMP_DIR/generated-construct-graph-extra-trace-ref.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-duplicate-input-ref.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for fact in report[0]["construct_graph"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("validator.graph.accepted:"):
        refs = fact.setdefault("input_refs", [])
        if not refs:
            raise SystemExit("construct graph acceptance fact has no input refs to duplicate")
        refs.append(refs[0])
        break
else:
    raise SystemExit("missing construct graph acceptance fact to pad with duplicate input ref")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-duplicate-input-ref.json" \
    > "$TMP_DIR/generated-construct-graph-duplicate-input-ref.maude" \
    2> "$TMP_DIR/generated-construct-graph-duplicate-input-ref.err"; then
    echo "expected construct graph bridge to reject duplicate validator input refs" >&2
    exit 1
  fi
  grep -q 'check report failed schema validation against check_report_v0.schema.json' \
    "$TMP_DIR/generated-construct-graph-duplicate-input-ref.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-duplicate-string-ref.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for node in report[0]["construct_graph"].get("nodes", []):
    refs = node.get("required_ports")
    if isinstance(refs, list) and refs:
        refs.append(refs[0])
        break
else:
    raise SystemExit("missing construct graph node port ref to duplicate")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-duplicate-string-ref.json" \
    > "$TMP_DIR/generated-construct-graph-duplicate-string-ref.maude" \
    2> "$TMP_DIR/generated-construct-graph-duplicate-string-ref.err"; then
    echo "expected construct graph bridge to reject duplicate graph string refs" >&2
    exit 1
  fi
  grep -q 'construct graph failed schema validation against construct_graph_v0.schema.json' \
    "$TMP_DIR/generated-construct-graph-duplicate-string-ref.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-duplicate-interface.json" <<'PY'
import copy
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for node in report[0]["construct_graph"].get("nodes", []):
    for field in ["declared_required_interfaces", "declared_provided_interfaces"]:
        interfaces = node.get(field)
        if isinstance(interfaces, list) and interfaces:
            interfaces.append(copy.deepcopy(interfaces[0]))
            json.dump(report, open(dest_path, "w"))
            raise SystemExit(0)
raise SystemExit("missing construct graph interface to duplicate")
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-duplicate-interface.json" \
    > "$TMP_DIR/generated-construct-graph-duplicate-interface.maude" \
    2> "$TMP_DIR/generated-construct-graph-duplicate-interface.err"; then
    echo "expected construct graph bridge to reject duplicate declared interfaces" >&2
    exit 1
  fi
  grep -q 'construct graph failed schema validation against construct_graph_v0.schema.json' \
    "$TMP_DIR/generated-construct-graph-duplicate-interface.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-duplicate-edge-ref.json" <<'PY'
import copy
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
edges = report[0]["construct_graph"].get("edges", [])
if not edges:
    raise SystemExit("missing construct graph edge to duplicate")
duplicate = copy.deepcopy(edges[0])
duplicate.setdefault("evidence", []).append("semantic-duplicate-edge-ref")
edges.append(duplicate)
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-duplicate-edge-ref.json" \
    > "$TMP_DIR/generated-construct-graph-duplicate-edge-ref.maude" \
    2> "$TMP_DIR/generated-construct-graph-duplicate-edge-ref.err"; then
    echo "expected construct graph bridge to reject duplicate edge refs" >&2
    exit 1
  fi
  grep -q 'construct graph edge refs not unique' \
    "$TMP_DIR/generated-construct-graph-duplicate-edge-ref.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-unknown-trace-predicate.json" <<'PY'
import copy
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
facts = report[0]["construct_graph"]["derived_facts"]
for fact in facts:
    if str(fact.get("predicate", "")).startswith("validator.graph.accepted:"):
        extra = copy.deepcopy(fact)
        extra["predicate"] = "validator.graph.stale_unknown_predicate"
        facts.append(extra)
        break
else:
    raise SystemExit("missing construct graph acceptance fact to clone")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-unknown-trace-predicate.json" \
    > "$TMP_DIR/generated-construct-graph-unknown-trace-predicate.maude" \
    2> "$TMP_DIR/generated-construct-graph-unknown-trace-predicate.err"; then
    echo "expected construct graph bridge to reject unknown validator trace predicates" >&2
    exit 1
  fi
  grep -q 'unexpected validator predicate' \
    "$TMP_DIR/generated-construct-graph-unknown-trace-predicate.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-construct-graph-missing-edge-ref-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
edges = report[0]["construct_graph"]["edges"]
if not edges:
    raise SystemExit("generated construct graph did not contain an edge to weaken")
edge = edges[0]
edge_ref = f'{edge["required_port_id"]}->{edge["provided_port_id"]}'
for fact in report[0]["construct_graph"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("validator.graph.accepted:"):
        fact["input_refs"] = [
            ref for ref in fact.get("input_refs", []) if ref != edge_ref
        ]
        break
else:
    raise SystemExit("missing construct graph acceptance fact to weaken")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-missing-edge-ref-trace.json" \
    > "$TMP_DIR/generated-construct-graph-missing-edge-ref-trace.maude" \
    2> "$TMP_DIR/generated-construct-graph-missing-edge-ref-trace.err"; then
    echo "expected construct graph bridge to reject graph acceptance without edge refs" >&2
    exit 1
  fi
  grep -q 'validator predicate input_refs incomplete' \
    "$TMP_DIR/generated-construct-graph-missing-edge-ref-trace.err"
  python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-check.json" \
    > "$TMP_DIR/generated-construct-graph.maude"
  python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-verified.json" \
    > "$TMP_DIR/generated-construct-graph-verified.maude"
)
generated_output="$(maude "$TMP_DIR/generated-construct-graph.maude")"
printf '%s\n' "$generated_output"
generated_verified_output="$(maude "$TMP_DIR/generated-construct-graph-verified.maude")"
printf '%s\n' "$generated_verified_output"
generated_no_solution="$(grep -c 'No solution\.' <<<"$generated_output" || true)"
generated_solution="$(grep -c '^Solution 1' <<<"$generated_output" || true)"
generated_verified_no_solution="$(grep -c 'No solution\.' <<<"$generated_verified_output" || true)"
generated_verified_solution="$(grep -c '^Solution 1' <<<"$generated_verified_output" || true)"
generated_expected_solution="$(cat "$TMP_DIR/generated-construct-graph-expected.txt")"
if [[ "$generated_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated construct graph: got $generated_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_solution" != "$generated_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated construct graph: got $generated_solution, expected $generated_expected_solution" >&2
  exit 1
fi
if [[ "$generated_verified_no_solution" != "0" ]]; then
  echo "unexpected No solution count for verified construct graph bundle: got $generated_verified_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_verified_solution" != "$generated_expected_solution" ]]; then
  echo "unexpected Solution 1 count for verified construct graph bundle: got $generated_verified_solution, expected $generated_expected_solution" >&2
  exit 1
fi

echo "== generated Maude from check-report lowered IR"
(
  cd "$ROOT"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" > "$TMP_DIR/generated-lowered-ir-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
entry = report[0]
graph = entry["construct_graph"]
lowered = entry["lowered_ir_report"]
print(
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3
)
if not lowered["core_objects"]:
    raise SystemExit("generated lowered IR report did not emit any core objects")
if len(graph["nodes"]) != len(lowered["node_lowerings"]):
    raise SystemExit("generated lowered IR report did not cover every graph node")
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-multi-entry.json" \
    > "$TMP_DIR/generated-lowered-ir-multi-entry.maude" \
    2> "$TMP_DIR/generated-lowered-ir-multi-entry.err"; then
    echo "expected lowered IR bridge to reject ambiguous multi-entry check reports" >&2
    exit 1
  fi
  grep -q 'pass --entry-index to select the artifact to lower' \
    "$TMP_DIR/generated-lowered-ir-multi-entry.err"
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    --entry-index 1 \
    "$TMP_DIR/generated-construct-graph-multi-entry.json" \
    > "$TMP_DIR/generated-lowered-ir-multi-entry-selected.maude"
  grep -q 'WHIPPLESCRIPT-GENERATED-LOWERED-IR' \
    "$TMP_DIR/generated-lowered-ir-multi-entry-selected.maude"
  cargo run --quiet -p whipplescript -- verify-report --emit lowered-ir \
    "$TMP_DIR/generated-construct-graph-check.json" \
    > "$TMP_DIR/generated-lowered-ir-verified.json"
  python3 - "$TMP_DIR/generated-lowered-ir-verified.json" "$TMP_DIR/generated-lowered-ir-verified-multi-entry.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
bundle = json.load(open(source_path))
entries = bundle.get("entries")
if not isinstance(entries, list) or len(entries) != 1:
    raise SystemExit(f"expected one verified lowered artifact entry, got {entries!r}")
bundle["entries"] = [entries[0], entries[0]]
json.dump(bundle, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-verified-multi-entry.json" \
    > "$TMP_DIR/generated-lowered-ir-verified-multi-entry.maude" \
    2> "$TMP_DIR/generated-lowered-ir-verified-multi-entry.err"; then
    echo "expected lowered IR bridge to reject ambiguous multi-entry verified bundles" >&2
    exit 1
  fi
  grep -q 'pass --entry-index to select the artifact to lower' \
    "$TMP_DIR/generated-lowered-ir-verified-multi-entry.err"
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    --entry-index 1 \
    "$TMP_DIR/generated-lowered-ir-verified-multi-entry.json" \
    > "$TMP_DIR/generated-lowered-ir-verified-multi-entry-selected.maude"
  grep -q 'WHIPPLESCRIPT-GENERATED-LOWERED-IR' \
    "$TMP_DIR/generated-lowered-ir-verified-multi-entry-selected.maude"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-invalid-schema.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
core_objects = report[0]["lowered_ir_report"]["core_objects"]
if not core_objects:
    raise SystemExit("missing lowered IR core object to invalidate")
del core_objects[0]["object_id"]
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-invalid-schema.json" \
    > "$TMP_DIR/generated-lowered-ir-invalid-schema.maude" \
    2> "$TMP_DIR/generated-lowered-ir-invalid-schema.err"; then
    echo "expected lowered IR bridge to reject schema-invalid lowered input" >&2
    exit 1
  fi
  grep -q 'lowered IR report failed schema validation against lowered_ir_report_v0.schema.json' \
    "$TMP_DIR/generated-lowered-ir-invalid-schema.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-stale-source.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
report[0]["lowered_ir_report"]["source_digest"] = "3333333333333333333333333333333333333333333333333333333333333333"
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-stale-source.json" \
    > "$TMP_DIR/generated-lowered-ir-stale-source.maude" \
    2> "$TMP_DIR/generated-lowered-ir-stale-source.err"; then
    echo "expected lowered IR bridge to reject stale lowered artifact identity" >&2
    exit 1
  fi
  grep -q 'source_digest .*does not match construct graph source_digest' \
    "$TMP_DIR/generated-lowered-ir-stale-source.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-missing-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
facts = report[0]["lowered_ir_report"]["derived_facts"]
report[0]["lowered_ir_report"]["derived_facts"] = [
    fact
    for fact in facts
    if not str(fact.get("predicate", "")).startswith("lowered_ir.validator.graph.runtime_boundary:")
]
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-missing-trace.json" \
    > "$TMP_DIR/generated-lowered-ir-missing-trace.maude" \
    2> "$TMP_DIR/generated-lowered-ir-missing-trace.err"; then
    echo "expected lowered IR bridge to reject missing validator trace" >&2
    exit 1
  fi
  grep -q 'lowered IR report derived_facts missing validator predicate' \
    "$TMP_DIR/generated-lowered-ir-missing-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-spoofed-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for fact in report[0]["lowered_ir_report"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("lowered_ir.validator.graph.runtime_boundary:"):
        fact["owner_subsystem"] = "compiler"
        break
else:
    raise SystemExit("missing lowered IR runtime boundary fact to spoof")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-spoofed-trace.json" \
    > "$TMP_DIR/generated-lowered-ir-spoofed-trace.maude" \
    2> "$TMP_DIR/generated-lowered-ir-spoofed-trace.err"; then
    echo "expected lowered IR bridge to reject spoofed validator trace owner" >&2
    exit 1
  fi
  grep -q 'lowered IR report derived_facts missing validator predicate' \
    "$TMP_DIR/generated-lowered-ir-spoofed-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-missing-node-preservation-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
facts = report[0]["lowered_ir_report"]["derived_facts"]
report[0]["lowered_ir_report"]["derived_facts"] = [
    fact
    for fact in facts
    if not str(fact.get("predicate", "")).startswith("lowered_ir.validator.node.preservation:")
]
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-missing-node-preservation-trace.json" \
    > "$TMP_DIR/generated-lowered-ir-missing-node-preservation-trace.maude" \
    2> "$TMP_DIR/generated-lowered-ir-missing-node-preservation-trace.err"; then
    echo "expected lowered IR bridge to reject missing node preservation validator trace" >&2
    exit 1
  fi
  grep -q 'lowered IR report derived_facts missing validator predicate' \
    "$TMP_DIR/generated-lowered-ir-missing-node-preservation-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-incomplete-trace.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
graph_id = report[0]["lowered_ir_report"]["graph_id"]
for fact in report[0]["lowered_ir_report"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("lowered_ir.validator.graph.runtime_boundary:"):
        fact["input_refs"] = [
            ref for ref in fact.get("input_refs", []) if ref != graph_id
        ]
        break
else:
    raise SystemExit("missing lowered IR runtime boundary fact to weaken")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-incomplete-trace.json" \
    > "$TMP_DIR/generated-lowered-ir-incomplete-trace.maude" \
    2> "$TMP_DIR/generated-lowered-ir-incomplete-trace.err"; then
    echo "expected lowered IR bridge to reject incomplete validator trace input refs" >&2
    exit 1
  fi
  grep -q 'validator predicate input_refs incomplete' \
    "$TMP_DIR/generated-lowered-ir-incomplete-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-duplicate-trace.json" <<'PY'
import copy
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
facts = report[0]["lowered_ir_report"]["derived_facts"]
for fact in facts:
    if str(fact.get("predicate", "")).startswith("lowered_ir.validator.graph.runtime_boundary:"):
        duplicate = copy.deepcopy(fact)
        duplicate.setdefault("diagnostic_span", {})["construct"] = (
            "semantic-duplicate-validator-predicate"
        )
        facts.append(duplicate)
        break
else:
    raise SystemExit("missing lowered IR runtime boundary fact to duplicate")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-duplicate-trace.json" \
    > "$TMP_DIR/generated-lowered-ir-duplicate-trace.maude" \
    2> "$TMP_DIR/generated-lowered-ir-duplicate-trace.err"; then
    echo "expected lowered IR bridge to reject duplicate validator trace" >&2
    exit 1
  fi
  grep -q 'duplicate validator predicate' \
    "$TMP_DIR/generated-lowered-ir-duplicate-trace.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-extra-trace-ref.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for fact in report[0]["lowered_ir_report"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("lowered_ir.validator.graph.runtime_boundary:"):
        fact.setdefault("input_refs", []).append("bogus:trace-ref")
        break
else:
    raise SystemExit("missing lowered IR runtime boundary fact to pad")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-extra-trace-ref.json" \
    > "$TMP_DIR/generated-lowered-ir-extra-trace-ref.maude" \
    2> "$TMP_DIR/generated-lowered-ir-extra-trace-ref.err"; then
    echo "expected lowered IR bridge to reject padded validator trace refs" >&2
    exit 1
  fi
  grep -q 'validator predicate input_refs unexpected' \
    "$TMP_DIR/generated-lowered-ir-extra-trace-ref.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-duplicate-input-ref.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for fact in report[0]["lowered_ir_report"]["derived_facts"]:
    if str(fact.get("predicate", "")).startswith("lowered_ir.validator.graph.runtime_boundary:"):
        refs = fact.setdefault("input_refs", [])
        if not refs:
            raise SystemExit("lowered IR runtime boundary fact has no input refs to duplicate")
        refs.append(refs[0])
        break
else:
    raise SystemExit("missing lowered IR runtime boundary fact to pad with duplicate input ref")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-duplicate-input-ref.json" \
    > "$TMP_DIR/generated-lowered-ir-duplicate-input-ref.maude" \
    2> "$TMP_DIR/generated-lowered-ir-duplicate-input-ref.err"; then
    echo "expected lowered IR bridge to reject duplicate validator input refs" >&2
    exit 1
  fi
  grep -q 'check report failed schema validation against check_report_v0.schema.json' \
    "$TMP_DIR/generated-lowered-ir-duplicate-input-ref.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-duplicate-witness-ref.json" <<'PY'
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
for lowering in report[0]["lowered_ir_report"].get("node_lowerings", []):
    refs = lowering.get("preserved_source_span_refs")
    if isinstance(refs, list) and refs:
        refs.append(refs[0])
        break
else:
    raise SystemExit("missing lowered IR node witness ref to duplicate")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-duplicate-witness-ref.json" \
    > "$TMP_DIR/generated-lowered-ir-duplicate-witness-ref.maude" \
    2> "$TMP_DIR/generated-lowered-ir-duplicate-witness-ref.err"; then
    echo "expected lowered IR bridge to reject duplicate lowering witness refs" >&2
    exit 1
  fi
  grep -q 'lowered IR report failed schema validation against lowered_ir_report_v0.schema.json' \
    "$TMP_DIR/generated-lowered-ir-duplicate-witness-ref.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-unknown-trace-predicate.json" <<'PY'
import copy
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
facts = report[0]["lowered_ir_report"]["derived_facts"]
for fact in facts:
    if str(fact.get("predicate", "")).startswith("lowered_ir.validator.graph.runtime_boundary:"):
        extra = copy.deepcopy(fact)
        extra["predicate"] = "lowered_ir.validator.graph.stale_unknown_predicate"
        facts.append(extra)
        break
else:
    raise SystemExit("missing lowered IR runtime boundary fact to clone")
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-unknown-trace-predicate.json" \
    > "$TMP_DIR/generated-lowered-ir-unknown-trace-predicate.maude" \
    2> "$TMP_DIR/generated-lowered-ir-unknown-trace-predicate.err"; then
    echo "expected lowered IR bridge to reject unknown validator trace predicates" >&2
    exit 1
  fi
  grep -q 'unexpected validator predicate' \
    "$TMP_DIR/generated-lowered-ir-unknown-trace-predicate.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-duplicate-node-lowering.json" <<'PY'
import copy
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
node_lowerings = report[0]["lowered_ir_report"].get("node_lowerings", [])
if not node_lowerings:
    raise SystemExit("missing lowered IR node lowering to duplicate")
duplicate = copy.deepcopy(node_lowerings[0])
duplicate.setdefault("preserved_provenance_refs", []).append(
    "semantic-duplicate-node-lowering"
)
node_lowerings.append(duplicate)
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-duplicate-node-lowering.json" \
    > "$TMP_DIR/generated-lowered-ir-duplicate-node-lowering.maude" \
    2> "$TMP_DIR/generated-lowered-ir-duplicate-node-lowering.err"; then
    echo "expected lowered IR bridge to reject duplicate node lowerings" >&2
    exit 1
  fi
  grep -q 'lowered IR report node lowering refs not unique' \
    "$TMP_DIR/generated-lowered-ir-duplicate-node-lowering.err"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-duplicate-core-object.json" <<'PY'
import copy
import json
import sys

source_path, dest_path = sys.argv[1], sys.argv[2]
report = json.load(open(source_path))
core_objects = report[0]["lowered_ir_report"].get("core_objects", [])
if not core_objects:
    raise SystemExit("missing lowered IR core object to duplicate")
duplicate = copy.deepcopy(core_objects[0])
duplicate.setdefault("source_span", {})["construct"] = "semantic-duplicate-core-object"
core_objects.append(duplicate)
json.dump(report, open(dest_path, "w"))
PY
  if python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-duplicate-core-object.json" \
    > "$TMP_DIR/generated-lowered-ir-duplicate-core-object.maude" \
    2> "$TMP_DIR/generated-lowered-ir-duplicate-core-object.err"; then
    echo "expected lowered IR bridge to reject duplicate core object IDs" >&2
    exit 1
  fi
  grep -q 'lowered IR report core object IDs not unique' \
    "$TMP_DIR/generated-lowered-ir-duplicate-core-object.err"
  for handoff_pair in \
    "event event_record" \
    "projection event_projection" \
    "diagnostic diagnostic_record"; do
    read -r handoff_kind handoff_entrypoint <<< "$handoff_pair"
    handoff_label="${handoff_kind}-${handoff_entrypoint}"
    python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-supported-${handoff_label}.json" "$handoff_kind" "$handoff_entrypoint" <<'PY'
import json
import sys

source_path, dest_path, object_kind, runtime_entrypoint = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
report = json.load(open(source_path))
lowered = report[0]["lowered_ir_report"]
core_object = next(
    (
        obj
        for obj in lowered["core_objects"]
        if obj.get("object_kind") == "effect"
        and obj.get("runtime_entrypoint") == "effect_graph_template"
    ),
    None,
)
if core_object is None:
    raise SystemExit("missing effect core object to mutate")
object_id = core_object["object_id"]
graph_id = lowered["graph_id"]
node_id = core_object.get("owner_ref")
if core_object.get("owner_kind") != "node" or not isinstance(node_id, str):
    raise SystemExit("supported handoff fixture expects a node-owned core object")
core_object["object_kind"] = object_kind
core_object["runtime_entrypoint"] = runtime_entrypoint
if object_kind == "event":
    core_object["entrypoint_refs"] = {"event": "deploy.finished"}
elif object_kind == "projection":
    core_object["entrypoint_refs"] = {
        "event": "deploy.finished",
        "fact": "schema:DeployFinished",
    }
elif object_kind == "diagnostic":
    core_object["entrypoint_refs"] = {"rule": "observe"}
else:
    raise SystemExit(f"unsupported object kind {object_kind}")
graph_node = None
for node in report[0]["construct_graph"]["nodes"]:
    if node.get("node_id") == node_id:
        node["allowed_core_object_kinds"] = [object_kind]
        node["allowed_runtime_entrypoints"] = [runtime_entrypoint]
        graph_node = node
        break
else:
    raise SystemExit(f"missing graph node {node_id} for supported handoff fixture")
lowering_output_kind = graph_node["lowering_output_kind"]
graph_output_predicate = f"validator.node.output:{node_id}:{lowering_output_kind}"
for fact in report[0]["construct_graph"].get("derived_facts", []):
    if (
        fact.get("owner_subsystem") == "construct_graph_validator"
        and fact.get("predicate") == graph_output_predicate
    ):
        fact["input_refs"] = sorted([
            node_id,
            lowering_output_kind,
            object_kind,
            runtime_entrypoint,
        ])
        break
else:
    raise SystemExit(f"missing construct graph validator fact {graph_output_predicate}")
node_lowering = next(
    (
        lowering
        for lowering in lowered["node_lowerings"]
        if lowering.get("node_id") == node_id
    ),
    None,
)
if node_lowering is None:
    raise SystemExit(f"missing node lowering {node_id} for supported handoff fixture")
lowering_class = node_lowering["lowering_class"]
objects_by_id = {obj["object_id"]: obj for obj in lowered["core_objects"]}
produced_object_ids = node_lowering["produced_core_object_refs"]


def sorted_refs(refs):
    return sorted(set(refs))


def produced_object_field_refs(field):
    refs = [graph_id, node_id]
    for produced_id in produced_object_ids:
        obj = objects_by_id[produced_id]
        refs.extend([produced_id, obj[field]])
    return sorted_refs(refs)


def produced_object_refs():
    return sorted_refs([graph_id, node_id, *produced_object_ids])


def output_compat_refs():
    refs = [
        graph_id,
        node_id,
        *graph_node["allowed_core_object_kinds"],
        *graph_node["allowed_runtime_entrypoints"],
    ]
    for produced_id in produced_object_ids:
        obj = objects_by_id[produced_id]
        refs.extend([produced_id, obj["object_kind"], obj["runtime_entrypoint"]])
    return sorted_refs(refs)


def entrypoint_refs():
    refs = [graph_id, object_id, object_kind, runtime_entrypoint]
    for key, value in core_object["entrypoint_refs"].items():
        refs.append(f"{object_id}#entrypoint_refs.{key}:{value}")
    return sorted_refs(refs)


def lifecycle_input_refs():
    refs = [
        graph_id,
        node_id,
        lowering_class,
        graph_node["construct_family"],
        graph_node["lifecycle_profile"],
    ]
    for produced_id in produced_object_ids:
        obj = objects_by_id[produced_id]
        refs.extend([produced_id, obj["object_kind"], obj["runtime_entrypoint"]])
    return sorted_refs(refs)


def set_fact(predicate, refs):
    for fact in lowered["derived_facts"]:
        if fact.get("predicate") == predicate:
            fact["input_refs"] = sorted_refs(refs)
            return
    raise SystemExit(f"missing lowered IR validator fact {predicate}")


runtime_boundary_refs = [graph_id]
no_runtime_input_refs = [f"lowered_ir.root.graph_id:{graph_id}"]
for obj in lowered["core_objects"]:
    runtime_boundary_refs.extend([
        obj["object_id"],
        obj["object_kind"],
        obj["runtime_entrypoint"],
    ])
    no_runtime_input_refs.append(
        "lowered_ir.runtime_boundary."
        f"{obj['object_id']}:{obj['object_kind']}:{obj['runtime_entrypoint']}"
    )

entrypoint_fact_seen = False
runtime_boundary_seen = False
no_runtime_input_seen = False
for fact in lowered["derived_facts"]:
    predicate = str(fact.get("predicate", ""))
    if predicate.startswith(f"lowered_ir.validator.core_object.entrypoint:{object_id}:"):
        fact["predicate"] = (
            "lowered_ir.validator.core_object.entrypoint:"
            f"{object_id}:{object_kind}:{runtime_entrypoint}"
        )
        fact["input_refs"] = entrypoint_refs()
        entrypoint_fact_seen = True
    if predicate.startswith("lowered_ir.validator.graph.runtime_boundary:"):
        fact["input_refs"] = sorted(set(runtime_boundary_refs))
        runtime_boundary_seen = True
    if predicate.startswith("lowered_ir.validator.graph.no_runtime_inputs:"):
        fact["input_refs"] = sorted(set(no_runtime_input_refs))
        no_runtime_input_seen = True
if not entrypoint_fact_seen:
    raise SystemExit("missing core object entrypoint validator fact to mutate")
if not runtime_boundary_seen:
    raise SystemExit("missing runtime boundary validator fact to mutate")
if not no_runtime_input_seen:
    raise SystemExit("missing no-runtime-input validator fact to mutate")
set_fact(
    f"lowered_ir.validator.node.lifecycle_inputs:{node_id}:{lowering_class}",
    lifecycle_input_refs(),
)
set_fact(
    f"lowered_ir.validator.node.lifecycle_inputs.object_kinds:{node_id}:{lowering_class}",
    produced_object_field_refs("object_kind"),
)
set_fact(
    f"lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:{node_id}:{lowering_class}",
    produced_object_field_refs("runtime_entrypoint"),
)
set_fact(f"lowered_ir.validator.node.output_compat:{node_id}", output_compat_refs())
set_fact(
    f"lowered_ir.validator.node.output_compat.allowed_core_object_kinds:{node_id}",
    [graph_id, node_id, *graph_node["allowed_core_object_kinds"]],
)
set_fact(
    f"lowered_ir.validator.node.output_compat.allowed_runtime_entrypoints:{node_id}",
    [graph_id, node_id, *graph_node["allowed_runtime_entrypoints"]],
)
set_fact(
    f"lowered_ir.validator.node.output_compat.produced_core_objects:{node_id}",
    produced_object_refs(),
)
set_fact(
    f"lowered_ir.validator.node.output_compat.object_kinds:{node_id}",
    produced_object_field_refs("object_kind"),
)
set_fact(
    f"lowered_ir.validator.node.output_compat.runtime_entrypoints:{node_id}",
    produced_object_field_refs("runtime_entrypoint"),
)
json.dump(report, open(dest_path, "w"))
PY
    python3 scripts/lowered-ir-to-maude.py \
      --platform-catalog "$PLATFORM_CATALOG_PATH" \
      --root "$ROOT" \
      "$TMP_DIR/generated-lowered-ir-supported-${handoff_label}.json" \
      > "$TMP_DIR/generated-lowered-ir-supported-${handoff_label}.maude"
    case "$handoff_kind" in
      event) grep -q 'eventEntrypoint' "$TMP_DIR/generated-lowered-ir-supported-${handoff_label}.maude" ;;
      projection) grep -q 'projectionEntrypoint' "$TMP_DIR/generated-lowered-ir-supported-${handoff_label}.maude" ;;
      diagnostic) grep -q 'diagnosticEntrypoint' "$TMP_DIR/generated-lowered-ir-supported-${handoff_label}.maude" ;;
    esac
  done
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-wide-required-node.json" "$TMP_DIR/generated-lowered-ir-wide-required-node-expected.txt" <<'PY'
import copy
import json
import sys

source_path, dest_path, expected_path = sys.argv[1], sys.argv[2], sys.argv[3]
report = json.load(open(source_path))
entry = report[0]
graph = entry["construct_graph"]
lowered = entry["lowered_ir_report"]
graph_id = lowered["graph_id"]
facts = lowered["derived_facts"]
graph_facts = graph["derived_facts"]

if not graph["edges"]:
    raise SystemExit("generated lowered IR report needs an edge to widen required ports")
edge = graph["edges"][0]
required_port_id = edge["required_port_id"]
provided_port_id = edge["provided_port_id"]
ports_by_id = {port["port_id"]: port for port in graph["ports"]}
nodes_by_id = {node["node_id"]: node for node in graph["nodes"]}
required_port = ports_by_id[required_port_id]
required_node = nodes_by_id[required_port["owner_node_id"]]

edge_lowering = next(
    (
        lowering
        for lowering in lowered["edge_lowerings"]
        if lowering["required_port_id"] == required_port_id
        and lowering["provided_port_id"] == provided_port_id
    ),
    None,
)
if edge_lowering is None:
    raise SystemExit("missing edge lowering to widen")


def add_fact(predicate, refs, span):
    facts.append({
        "predicate": predicate,
        "owner_subsystem": "lowered_ir_validator",
        "input_refs": refs,
        "diagnostic_span": copy.deepcopy(span),
    })


def extend_fact(predicate, refs):
    for fact in facts:
        if fact.get("predicate") == predicate:
            input_refs = fact.setdefault("input_refs", [])
            for ref in refs:
                if ref not in input_refs:
                    input_refs.append(ref)
            return
    raise SystemExit(f"missing lowered IR validator fact {predicate}")


def add_graph_fact(predicate, refs, span):
    graph_facts.append({
        "predicate": predicate,
        "owner_subsystem": "construct_graph_validator",
        "input_refs": refs,
        "diagnostic_span": copy.deepcopy(span),
    })


def extend_graph_fact(predicate, refs):
    for fact in graph_facts:
        if fact.get("predicate") == predicate:
            input_refs = fact.setdefault("input_refs", [])
            for ref in refs:
                if ref not in input_refs:
                    input_refs.append(ref)
            return
    raise SystemExit(f"missing construct graph validator fact {predicate}")


def labeled(owner, label, value):
    return [f"{owner}#{label}:{value}"] if isinstance(value, str) and value else []


def graph_port_profile_refs(port):
    port_id = port["port_id"]
    refs = [port_id]
    for field in [
        "owner_node_id",
        "direction",
        "kind",
        "type",
        "phase",
        "contract_version",
        "cardinality",
    ]:
        refs.extend(labeled(port_id, field, port.get(field)))
    refs.append(f"{port_id}#resource_identity:{port.get('resource_identity') or '<none>'}")
    return refs


def graph_port_validation_refs(role, port):
    port_id = port["port_id"]
    refs = []
    for field in [
        "owner_node_id",
        "direction",
        "kind",
        "type",
        "phase",
        "contract_version",
        "cardinality",
    ]:
        refs.extend(labeled(port_id, f"{role}.{field}", port.get(field)))
    refs.append(f"{port_id}#{role}.resource_identity:{port.get('resource_identity') or '<none>'}")
    return refs


def graph_edge_validation_refs(edge, required, provided):
    ref = f'{edge["required_port_id"]}->{edge["provided_port_id"]}'
    refs = [ref, edge["required_port_id"], edge["provider_node_id"], edge["provided_port_id"]]
    refs.extend(labeled(ref, "resolution_reason", edge.get("resolution_reason")))
    for evidence in edge.get("evidence", []):
        if isinstance(evidence, str) and evidence:
            refs.append(f"{ref}#evidence:{evidence}")
    refs.extend(graph_port_validation_refs("required", required))
    refs.extend(graph_port_validation_refs("provided", provided))
    return refs


new_edge_refs = []
new_port_ids = []
for index in range(3):
    new_required_id = f"{required_port_id}:wide:{index}"
    new_edge_ref = f"{new_required_id}->{provided_port_id}"
    new_core_relation = f"{edge_lowering['core_relation_ref']}:wide:{index}"

    new_port = copy.deepcopy(required_port)
    new_port["port_id"] = new_required_id
    graph["ports"].append(new_port)
    required_node["required_ports"].append(new_required_id)

    new_edge = copy.deepcopy(edge)
    new_edge["required_port_id"] = new_required_id
    graph["edges"].append(new_edge)
    new_port_ids.append(new_required_id)

    new_lowering = copy.deepcopy(edge_lowering)
    new_lowering["required_port_id"] = new_required_id
    new_lowering["core_relation_ref"] = new_core_relation
    new_lowering["produced_core_object_refs"] = []
    new_lowering["preserved_type_refs"] = []
    new_lowering["preserved_resource_refs"] = []
    new_lowering["preserved_capability_refs"] = []
    new_lowering["preserved_version_refs"] = []
    new_lowering["preserved_span_refs"] = []
    new_lowering["preserved_cardinality_refs"] = []
    new_lowering["preserved_provenance_refs"] = []
    lowered["edge_lowerings"].append(new_lowering)

    add_fact(
        f"lowered_ir.validator.edge.lowered:{new_edge_ref}",
        [graph_id, new_edge_ref, new_required_id, provided_port_id],
        required_port["source_span"],
    )
    add_fact(
        f"lowered_ir.validator.edge.preservation:{new_edge_ref}",
        [graph_id, new_edge_ref, new_required_id, provided_port_id, new_core_relation],
        required_port["source_span"],
    )
    for suffix, refs in [
        ("required_port", [graph_id, new_edge_ref, new_required_id]),
        ("provided_port", [graph_id, new_edge_ref, provided_port_id]),
        ("core_relation", [graph_id, new_edge_ref, new_core_relation]),
        ("produced_core_objects", [graph_id, new_edge_ref]),
        ("type", [graph_id, new_edge_ref]),
        ("resource", [graph_id, new_edge_ref]),
        ("capability", [graph_id, new_edge_ref]),
        ("version", [graph_id, new_edge_ref]),
        ("span", [graph_id, new_edge_ref]),
        ("cardinality", [graph_id, new_edge_ref]),
        ("provenance", [graph_id, new_edge_ref]),
    ]:
        add_fact(
            f"lowered_ir.validator.edge.preservation.{suffix}:{new_edge_ref}",
            refs,
            required_port["source_span"],
        )
    new_edge_refs.append(new_edge_ref)

    add_graph_fact(
        f"validator.port.profile:{new_required_id}",
        graph_port_profile_refs(new_port),
        new_port["source_span"],
    )
    add_graph_fact(
        f"validator.port.owner_consistent:{new_required_id}",
        [new_required_id, required_node["node_id"]],
        new_port["source_span"],
    )
    add_graph_fact(
        f"validator.cardinality.exactly-one.satisfied:{new_required_id}",
        [new_required_id, new_edge_ref],
        new_port["source_span"],
    )
    edge_refs = graph_edge_validation_refs(new_edge, new_port, ports_by_id[provided_port_id])
    for predicate in [
        "validator.edge.endpoints_valid",
        "validator.edge.kind_compatible",
        "validator.edge.type_compatible",
        "validator.edge.phase_compatible",
        "validator.edge.version_compatible",
        "validator.edge.resource_compatible",
    ]:
        add_graph_fact(f"{predicate}:{new_edge_ref}", edge_refs, new_port["source_span"])

extend_fact(f"lowered_ir.validator.graph.coverage:{graph_id}", new_edge_refs)
extend_fact(
    f"lowered_ir.validator.graph.report_complete:{graph_id}",
    [f"lowered_ir.inventory.edge_lowering:{ref}" for ref in new_edge_refs],
)
extend_fact(f"lowered_ir.validator.graph.edge_lowerings_unique:{graph_id}", new_edge_refs)
extend_graph_fact(f"validator.graph.port_ids_unique:{graph_id}", new_port_ids)
extend_graph_fact(f"validator.graph.edge_refs_unique:{graph_id}", new_edge_refs)
extend_graph_fact(f"validator.graph.accepted:{graph_id}", [*new_port_ids, *new_edge_refs])
extend_graph_fact(f"validator.node.interfaces:{required_node['node_id']}", new_port_ids)
extend_graph_fact(f"validator.node.ports_consistent:{required_node['node_id']}", new_port_ids)

json.dump(report, open(dest_path, "w"))
print(
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3,
    file=open(expected_path, "w"),
)
PY
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-wide-required-node.json" \
    > "$TMP_DIR/generated-lowered-ir-wide-required-node.maude"
  grep -q 'nodeNeedsEdges(.*edgeCons(edgeId' "$TMP_DIR/generated-lowered-ir-wide-required-node.maude"
  grep -q 'edgeLoweringPreserved([^,]*, [^,]*, [^,]*, [^)]*)' \
    "$TMP_DIR/generated-lowered-ir-wide-required-node.maude"
  if grep -q 'nodeNeeds[0-9]' "$TMP_DIR/generated-lowered-ir-wide-required-node.maude"; then
    echo "generated lowered IR bridge emitted arity-specific nodeNeeds facts" >&2
    exit 1
  fi
  if grep -q 'nodeNeeds(.*portCons' "$TMP_DIR/generated-lowered-ir-wide-required-node.maude"; then
    echo "generated lowered IR bridge emitted required-port-only nodeNeeds facts" >&2
    exit 1
  fi
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-multi-owner.json" "$TMP_DIR/generated-lowered-ir-multi-owner-expected.txt" <<'PY'
import copy
import json
import sys

source_path, dest_path, expected_path = sys.argv[1], sys.argv[2], sys.argv[3]
report = json.load(open(source_path))
entry = report[0]
graph = entry["construct_graph"]
lowered = entry["lowered_ir_report"]
graph_id = lowered["graph_id"]
facts = lowered["derived_facts"]
source_span = copy.deepcopy(lowered["core_objects"][0]["source_span"])

if not graph["edges"]:
    raise SystemExit("generated lowered IR report needs an edge for multi-owner coverage")
if not graph["effect_dependencies"]:
    raise SystemExit("generated lowered IR report needs a dependency for multi-owner coverage")

edge = graph["edges"][0]
edge_ref = f'{edge["required_port_id"]}->{edge["provided_port_id"]}'
edge_obj_id = "core:effect:bridge-multi-edge-owner"
dependency = graph["effect_dependencies"][0]
dependency_ref = dependency["dependency_ref"]
dependency_obj_id = "core:effect:bridge-multi-dependency-owner"

edge_obj = {
    "object_kind": "effect",
    "object_id": edge_obj_id,
    "owner_kind": "edge",
    "owner_ref": edge_ref,
    "runtime_entrypoint": "effect_graph_template",
    "source_span": copy.deepcopy(source_span),
}
dependency_obj = {
    "object_kind": "effect",
    "object_id": dependency_obj_id,
    "owner_kind": "dependency",
    "owner_ref": dependency_ref,
    "runtime_entrypoint": "effect_graph_template",
    "source_span": copy.deepcopy(source_span),
}
lowered["core_objects"].extend([edge_obj, dependency_obj])

for lowering in lowered["edge_lowerings"]:
    if (
        lowering["required_port_id"] == edge["required_port_id"]
        and lowering["provided_port_id"] == edge["provided_port_id"]
    ):
        lowering["produced_core_object_refs"].append(edge_obj_id)
        break
else:
    raise SystemExit(f"missing edge lowering for {edge_ref}")

for lowering in lowered["dependency_lowerings"]:
    if lowering["dependency_ref"] == dependency_ref:
        lowering["produced_core_object_refs"].append(dependency_obj_id)
        break
else:
    raise SystemExit(f"missing dependency lowering for {dependency_ref}")


def extend_fact(predicate, refs):
    for fact in facts:
        if fact.get("predicate") == predicate:
            input_refs = fact.setdefault("input_refs", [])
            for ref in refs:
                if ref not in input_refs:
                    input_refs.append(ref)
            return
    raise SystemExit(f"missing lowered IR validator fact {predicate}")


def add_fact(predicate, refs):
    facts.append({
        "predicate": predicate,
        "owner_subsystem": "lowered_ir_validator",
        "input_refs": refs,
        "diagnostic_span": copy.deepcopy(source_span),
    })


extend_fact(f"lowered_ir.validator.edge.lowered:{edge_ref}", [edge_obj_id])
extend_fact(f"lowered_ir.validator.edge.preservation:{edge_ref}", [edge_obj_id])
extend_fact(
    f"lowered_ir.validator.edge.preservation.produced_core_objects:{edge_ref}",
    [edge_obj_id],
)
extend_fact(
    f"lowered_ir.validator.dependency.lowered:{dependency_ref}",
    [dependency_obj_id],
)
extend_fact(
    f"lowered_ir.validator.dependency.preservation:{dependency_ref}",
    [dependency_obj_id],
)
extend_fact(
    f"lowered_ir.validator.dependency.preservation.produced_core_objects:{dependency_ref}",
    [dependency_obj_id],
)
add_fact(
    "lowered_ir.validator.core_object.entrypoint:"
    f"{edge_obj_id}:effect:effect_graph_template",
    [graph_id, edge_obj_id, "effect", "effect_graph_template"],
)
add_fact(
    f"lowered_ir.validator.core_object.owner:{edge_obj_id}:edge:{edge_ref}",
    [graph_id, edge_obj_id, "edge", edge_ref],
)
add_fact(
    "lowered_ir.validator.core_object.entrypoint:"
    f"{dependency_obj_id}:effect:effect_graph_template",
    [graph_id, dependency_obj_id, "effect", "effect_graph_template"],
)
add_fact(
    "lowered_ir.validator.core_object.owner:"
    f"{dependency_obj_id}:dependency:{dependency_ref}",
    [graph_id, dependency_obj_id, "dependency", dependency_ref],
)
extend_fact(
    f"lowered_ir.validator.graph.coverage:{graph_id}",
    [edge_obj_id, dependency_obj_id],
)
extend_fact(
    f"lowered_ir.validator.graph.report_complete:{graph_id}",
    [
        f"lowered_ir.inventory.core_object:{edge_obj_id}",
        f"lowered_ir.inventory.core_object:{dependency_obj_id}",
    ],
)
extend_fact(
    f"lowered_ir.validator.graph.owner_unique:{graph_id}",
    [edge_obj_id, "edge", edge_ref, dependency_obj_id, "dependency", dependency_ref],
)
extend_fact(
    f"lowered_ir.validator.graph.runtime_boundary:{graph_id}",
    [
        edge_obj_id,
        "effect",
        "effect_graph_template",
        dependency_obj_id,
        "effect",
        "effect_graph_template",
    ],
)
extend_fact(
    f"lowered_ir.validator.graph.no_runtime_inputs:{graph_id}",
    [
        f"lowered_ir.runtime_boundary.{edge_obj_id}:effect:effect_graph_template",
        f"lowered_ir.runtime_boundary.{dependency_obj_id}:effect:effect_graph_template",
    ],
)
extend_fact(
    f"lowered_ir.validator.graph.core_object_ids_unique:{graph_id}",
    [edge_obj_id, dependency_obj_id],
)
json.dump(report, open(dest_path, "w"))
print(
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3,
    file=open(expected_path, "w"),
)
PY
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-multi-owner.json" \
    > "$TMP_DIR/generated-lowered-ir-multi-owner.maude"
  grep -q 'edgeCoreObjects(.*coreObjectCons' "$TMP_DIR/generated-lowered-ir-multi-owner.maude"
  grep -q 'dependencyCoreObjects(.*coreObjectCons' "$TMP_DIR/generated-lowered-ir-multi-owner.maude"
  python3 - "$TMP_DIR/generated-construct-graph-check.json" "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects.json" "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects-expected.txt" <<'PY'
import copy
import json
import sys

source_path, dest_path, expected_path = sys.argv[1], sys.argv[2], sys.argv[3]
report = json.load(open(source_path))
entry = report[0]
lowered = entry["lowered_ir_report"]
graph_id = lowered["graph_id"]
facts = lowered["derived_facts"]

base_object = next(
    (
        obj
        for obj in lowered["core_objects"]
        if obj.get("owner_kind") == "node"
        and obj.get("object_kind") == "effect"
        and obj.get("runtime_entrypoint") == "effect_graph_template"
    ),
    None,
)
if base_object is None:
    raise SystemExit("missing node-owned effect object to widen")

node_id = base_object["owner_ref"]
node_lowering = next(
    (
        lowering
        for lowering in lowered["node_lowerings"]
        if lowering["node_id"] == node_id
    ),
    None,
)
if node_lowering is None:
    raise SystemExit(f"missing node lowering for {node_id}")

new_object_ids = [
    f"{base_object['object_id']}:wide-node-owned:{index}"
    for index in range(2)
]
for object_id in new_object_ids:
    new_object = copy.deepcopy(base_object)
    new_object["object_id"] = object_id
    lowered["core_objects"].append(new_object)
    node_lowering["produced_core_object_refs"].append(object_id)


def extend_fact(predicate, refs):
    for fact in facts:
        if fact.get("predicate") == predicate:
            input_refs = fact.setdefault("input_refs", [])
            for ref in refs:
                if ref not in input_refs:
                    input_refs.append(ref)
            return
    raise SystemExit(f"missing lowered IR validator fact {predicate}")


def add_fact(predicate, refs):
    facts.append({
        "predicate": predicate,
        "owner_subsystem": "lowered_ir_validator",
        "input_refs": refs,
        "diagnostic_span": copy.deepcopy(base_object["source_span"]),
    })


lowering_class = node_lowering["lowering_class"]
extend_fact(f"lowered_ir.validator.node.lowered:{node_id}", new_object_ids)
extend_fact(f"lowered_ir.validator.node.preservation:{node_id}", new_object_ids)
extend_fact(
    f"lowered_ir.validator.node.preservation.produced_core_objects:{node_id}",
    new_object_ids,
)
extend_fact(
    f"lowered_ir.validator.node.output_compat:{node_id}",
    [
        ref
        for object_id in new_object_ids
        for ref in [object_id, "effect", "effect_graph_template"]
    ],
)
extend_fact(
    f"lowered_ir.validator.node.lifecycle_inputs:{node_id}:{lowering_class}",
    [
        ref
        for object_id in new_object_ids
        for ref in [object_id, "effect", "effect_graph_template"]
    ],
)
extend_fact(
    f"lowered_ir.validator.node.lifecycle_inputs.produced_core_objects:{node_id}:{lowering_class}",
    new_object_ids,
)
extend_fact(
    f"lowered_ir.validator.node.lifecycle_inputs.object_kinds:{node_id}:{lowering_class}",
    [
        ref
        for object_id in new_object_ids
        for ref in [object_id, "effect"]
    ],
)
extend_fact(
    f"lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:{node_id}:{lowering_class}",
    [
        ref
        for object_id in new_object_ids
        for ref in [object_id, "effect_graph_template"]
    ],
)
extend_fact(
    f"lowered_ir.validator.node.output_compat.produced_core_objects:{node_id}",
    new_object_ids,
)
extend_fact(
    f"lowered_ir.validator.node.output_compat.object_kinds:{node_id}",
    [
        ref
        for object_id in new_object_ids
        for ref in [object_id, "effect"]
    ],
)
extend_fact(
    f"lowered_ir.validator.node.output_compat.runtime_entrypoints:{node_id}",
    [
        ref
        for object_id in new_object_ids
        for ref in [object_id, "effect_graph_template"]
    ],
)

for object_id in new_object_ids:
    add_fact(
        "lowered_ir.validator.core_object.entrypoint:"
        f"{object_id}:effect:effect_graph_template",
        [graph_id, object_id, "effect", "effect_graph_template"],
    )
    add_fact(
        f"lowered_ir.validator.core_object.owner:{object_id}:node:{node_id}",
        [graph_id, object_id, "node", node_id],
    )

extend_fact(f"lowered_ir.validator.graph.coverage:{graph_id}", new_object_ids)
extend_fact(
    f"lowered_ir.validator.graph.report_complete:{graph_id}",
    [f"lowered_ir.inventory.core_object:{object_id}" for object_id in new_object_ids],
)
extend_fact(
    f"lowered_ir.validator.graph.owner_unique:{graph_id}",
    [ref for object_id in new_object_ids for ref in [object_id, "node", node_id]],
)
extend_fact(
    f"lowered_ir.validator.graph.runtime_boundary:{graph_id}",
    [
        ref
        for object_id in new_object_ids
        for ref in [object_id, "effect", "effect_graph_template"]
    ],
)
extend_fact(
    f"lowered_ir.validator.graph.no_runtime_inputs:{graph_id}",
    [
        f"lowered_ir.runtime_boundary.{object_id}:effect:effect_graph_template"
        for object_id in new_object_ids
    ],
)
extend_fact(
    f"lowered_ir.validator.graph.core_object_ids_unique:{graph_id}",
    new_object_ids,
)

json.dump(report, open(dest_path, "w"))
print(
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3,
    file=open(expected_path, "w"),
)
PY
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects.json" \
    > "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects.maude"
  grep -q 'nodeCoreObjects(.*coreObjectCons' \
    "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects.maude"
  grep -q 'nodeClassOutput(.*nodeClassOutputCons' \
    "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects.maude"
  grep -q 'classCoreOutputs(.*classOutputCons' \
    "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects.maude"
  if grep -q 'nodeCoreObjects[0-9]\|nodeClassOutput[0-9]\|classCoreOutputs[0-9]' \
    "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects.maude"; then
    echo "generated lowered IR bridge emitted arity-specific node output facts" >&2
    exit 1
  fi
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-construct-graph-check.json" \
    > "$TMP_DIR/generated-lowered-ir.maude"
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-lowered-ir-verified.json" \
    > "$TMP_DIR/generated-lowered-ir-verified.maude"
)
generated_lowered_output="$(maude "$TMP_DIR/generated-lowered-ir.maude")"
printf '%s\n' "$generated_lowered_output"
generated_lowered_verified_output="$(maude "$TMP_DIR/generated-lowered-ir-verified.maude")"
printf '%s\n' "$generated_lowered_verified_output"
generated_lowered_no_solution="$(grep -c 'No solution\.' <<<"$generated_lowered_output" || true)"
generated_lowered_solution="$(grep -c '^Solution 1' <<<"$generated_lowered_output" || true)"
generated_lowered_verified_no_solution="$(grep -c 'No solution\.' <<<"$generated_lowered_verified_output" || true)"
generated_lowered_verified_solution="$(grep -c '^Solution 1' <<<"$generated_lowered_verified_output" || true)"
generated_lowered_expected_solution="$(cat "$TMP_DIR/generated-lowered-ir-expected.txt")"
if [[ "$generated_lowered_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated lowered IR: got $generated_lowered_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_lowered_solution" != "$generated_lowered_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated lowered IR: got $generated_lowered_solution, expected $generated_lowered_expected_solution" >&2
  exit 1
fi
if [[ "$generated_lowered_verified_no_solution" != "0" ]]; then
  echo "unexpected No solution count for verified lowered IR bundle: got $generated_lowered_verified_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_lowered_verified_solution" != "$generated_lowered_expected_solution" ]]; then
  echo "unexpected Solution 1 count for verified lowered IR bundle: got $generated_lowered_verified_solution, expected $generated_lowered_expected_solution" >&2
  exit 1
fi
generated_multi_owner_output="$(maude "$TMP_DIR/generated-lowered-ir-multi-owner.maude")"
printf '%s\n' "$generated_multi_owner_output"
generated_multi_owner_no_solution="$(grep -c 'No solution\.' <<<"$generated_multi_owner_output" || true)"
generated_multi_owner_solution="$(grep -c '^Solution 1' <<<"$generated_multi_owner_output" || true)"
generated_multi_owner_expected_solution="$(cat "$TMP_DIR/generated-lowered-ir-multi-owner-expected.txt")"
if [[ "$generated_multi_owner_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated lowered IR multi-owner fixture: got $generated_multi_owner_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_multi_owner_solution" != "$generated_multi_owner_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated lowered IR multi-owner fixture: got $generated_multi_owner_solution, expected $generated_multi_owner_expected_solution" >&2
  exit 1
fi
generated_wide_node_owned_output="$(maude "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects.maude")"
printf '%s\n' "$generated_wide_node_owned_output"
generated_wide_node_owned_no_solution="$(grep -c 'No solution\.' <<<"$generated_wide_node_owned_output" || true)"
generated_wide_node_owned_solution="$(grep -c '^Solution 1' <<<"$generated_wide_node_owned_output" || true)"
generated_wide_node_owned_expected_solution="$(cat "$TMP_DIR/generated-lowered-ir-wide-node-owned-objects-expected.txt")"
if [[ "$generated_wide_node_owned_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated lowered IR wide-node-owned-objects fixture: got $generated_wide_node_owned_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_wide_node_owned_solution" != "$generated_wide_node_owned_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated lowered IR wide-node-owned-objects fixture: got $generated_wide_node_owned_solution, expected $generated_wide_node_owned_expected_solution" >&2
  exit 1
fi
generated_wide_required_output="$(maude "$TMP_DIR/generated-lowered-ir-wide-required-node.maude")"
printf '%s\n' "$generated_wide_required_output"
generated_wide_required_no_solution="$(grep -c 'No solution\.' <<<"$generated_wide_required_output" || true)"
generated_wide_required_solution="$(grep -c '^Solution 1' <<<"$generated_wide_required_output" || true)"
generated_wide_required_expected_solution="$(cat "$TMP_DIR/generated-lowered-ir-wide-required-node-expected.txt")"
if [[ "$generated_wide_required_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated lowered IR wide-required-node fixture: got $generated_wide_required_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_wide_required_solution" != "$generated_wide_required_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated lowered IR wide-required-node fixture: got $generated_wide_required_solution, expected $generated_wide_required_expected_solution" >&2
  exit 1
fi

echo "== generated Maude from compile-report artifacts"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- --json compile \
    examples/package-memory.whip \
    > "$TMP_DIR/generated-compile-report.json"
  python3 - "$TMP_DIR/generated-compile-report.json" > "$TMP_DIR/generated-compile-construct-graph-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
graph = report["construct_graph"]
print(len(graph["nodes"]) + len(graph["edges"]) + 2)
PY
  python3 - "$TMP_DIR/generated-compile-report.json" > "$TMP_DIR/generated-compile-lowered-ir-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
graph = report["construct_graph"]
lowered = report["lowered_ir_report"]
print(
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3
)
if not lowered["core_objects"]:
    raise SystemExit("generated compile lowered IR report did not emit any core objects")
if len(graph["nodes"]) != len(lowered["node_lowerings"]):
    raise SystemExit("generated compile lowered IR report did not cover every graph node")
PY
  python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-compile-report.json" \
    > "$TMP_DIR/generated-compile-construct-graph.maude"
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-compile-report.json" \
    > "$TMP_DIR/generated-compile-lowered-ir.maude"
)
generated_compile_graph_output="$(maude "$TMP_DIR/generated-compile-construct-graph.maude")"
printf '%s\n' "$generated_compile_graph_output"
generated_compile_graph_no_solution="$(grep -c 'No solution\.' <<<"$generated_compile_graph_output" || true)"
generated_compile_graph_solution="$(grep -c '^Solution 1' <<<"$generated_compile_graph_output" || true)"
generated_compile_graph_expected_solution="$(cat "$TMP_DIR/generated-compile-construct-graph-expected.txt")"
if [[ "$generated_compile_graph_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated compile construct graph: got $generated_compile_graph_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_compile_graph_solution" != "$generated_compile_graph_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated compile construct graph: got $generated_compile_graph_solution, expected $generated_compile_graph_expected_solution" >&2
  exit 1
fi
generated_compile_lowered_output="$(maude "$TMP_DIR/generated-compile-lowered-ir.maude")"
printf '%s\n' "$generated_compile_lowered_output"
generated_compile_lowered_no_solution="$(grep -c 'No solution\.' <<<"$generated_compile_lowered_output" || true)"
generated_compile_lowered_solution="$(grep -c '^Solution 1' <<<"$generated_compile_lowered_output" || true)"
generated_compile_lowered_expected_solution="$(cat "$TMP_DIR/generated-compile-lowered-ir-expected.txt")"
if [[ "$generated_compile_lowered_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated compile lowered IR: got $generated_compile_lowered_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_compile_lowered_solution" != "$generated_compile_lowered_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated compile lowered IR: got $generated_compile_lowered_solution, expected $generated_compile_lowered_expected_solution" >&2
  exit 1
fi

echo "== generated Maude from event/rule/assertion construct graph"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- --json check \
    examples/event-bridge.whip \
    > "$TMP_DIR/generated-event-bridge-check.json"
  python3 - "$TMP_DIR/generated-event-bridge-check.json" > "$TMP_DIR/generated-event-bridge-construct-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
entry = report[0]
graph = entry["construct_graph"]
print(len(graph["nodes"]) + len(graph["edges"]) + 2)
lowering_classes = {node["lowering_class"] for node in graph["nodes"]}
construct_families = {node["construct_family"] for node in graph["nodes"]}
required_lowerings = {
    "assertion_check",
    "rule_template",
    "metadata",
    "core_effect",
}
missing_lowerings = sorted(required_lowerings - lowering_classes)
if missing_lowerings:
    raise SystemExit(f"event bridge fixture missing construct lowerings: {missing_lowerings}")
required_families = {
    "assertion",
    "rule",
    "projection_read",
    "effect_operation",
}
missing_families = sorted(required_families - construct_families)
if missing_families:
    raise SystemExit(f"event bridge fixture missing construct families: {missing_families}")
PY
  python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-event-bridge-check.json" \
    > "$TMP_DIR/generated-event-bridge-construct-graph.maude"
)
generated_event_bridge_graph_output="$(maude "$TMP_DIR/generated-event-bridge-construct-graph.maude")"
printf '%s\n' "$generated_event_bridge_graph_output"
generated_event_bridge_graph_no_solution="$(grep -c 'No solution\.' <<<"$generated_event_bridge_graph_output" || true)"
generated_event_bridge_graph_solution="$(grep -c '^Solution 1' <<<"$generated_event_bridge_graph_output" || true)"
generated_event_bridge_graph_expected_solution="$(cat "$TMP_DIR/generated-event-bridge-construct-expected.txt")"
if [[ "$generated_event_bridge_graph_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated event/rule/assertion construct graph: got $generated_event_bridge_graph_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_event_bridge_graph_solution" != "$generated_event_bridge_graph_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated event/rule/assertion construct graph: got $generated_event_bridge_graph_solution, expected $generated_event_bridge_graph_expected_solution" >&2
  exit 1
fi

echo "== generated Maude from event/rule/assertion lowered IR"
(
  cd "$ROOT"
  python3 - "$TMP_DIR/generated-event-bridge-check.json" > "$TMP_DIR/generated-event-bridge-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
entry = report[0]
graph = entry["construct_graph"]
lowered = entry["lowered_ir_report"]
print(
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3
)
lowering_classes = {node["lowering_class"] for node in graph["nodes"]}
construct_families = {node["construct_family"] for node in graph["nodes"]}
required_lowerings = {"assertion_check", "rule_template", "metadata", "core_effect"}
missing_lowerings = sorted(required_lowerings - lowering_classes)
if missing_lowerings:
    raise SystemExit(f"event bridge fixture missing construct lowerings: {missing_lowerings}")
required_families = {"assertion", "rule", "projection_read", "effect_operation"}
missing_families = sorted(required_families - construct_families)
if missing_families:
    raise SystemExit(f"event bridge fixture missing construct families: {missing_families}")
object_kinds = {obj["object_kind"] for obj in lowered["core_objects"]}
required_objects = {"assertion", "rule", "effect"}
missing_objects = sorted(required_objects - object_kinds)
if missing_objects:
    raise SystemExit(f"event bridge fixture missing lowered core objects: {missing_objects}")
PY
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-event-bridge-check.json" \
    > "$TMP_DIR/generated-event-bridge-lowered-ir.maude"
  grep -q 'assertionCheckLowering' "$TMP_DIR/generated-event-bridge-lowered-ir.maude"
  grep -q 'ruleTemplateLowering' "$TMP_DIR/generated-event-bridge-lowered-ir.maude"
)
generated_event_bridge_output="$(maude "$TMP_DIR/generated-event-bridge-lowered-ir.maude")"
printf '%s\n' "$generated_event_bridge_output"
generated_event_bridge_no_solution="$(grep -c 'No solution\.' <<<"$generated_event_bridge_output" || true)"
generated_event_bridge_solution="$(grep -c '^Solution 1' <<<"$generated_event_bridge_output" || true)"
generated_event_bridge_expected_solution="$(cat "$TMP_DIR/generated-event-bridge-expected.txt")"
if [[ "$generated_event_bridge_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated event/rule/assertion lowered IR: got $generated_event_bridge_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_event_bridge_solution" != "$generated_event_bridge_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated event/rule/assertion lowered IR: got $generated_event_bridge_solution, expected $generated_event_bridge_expected_solution" >&2
  exit 1
fi

echo "== generated Maude from schedule construct graph"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- --json check \
    examples/scheduled-escalation.whip \
    > "$TMP_DIR/generated-schedule-check.json"
  python3 - "$TMP_DIR/generated-schedule-check.json" > "$TMP_DIR/generated-schedule-construct-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
entry = report[0]
graph = entry["construct_graph"]
print(len(graph["nodes"]) + len(graph["edges"]) + 2)
lowering_classes = {node["lowering_class"] for node in graph["nodes"]}
construct_families = {node["construct_family"] for node in graph["nodes"]}
if "schedule_emitter" not in lowering_classes:
    raise SystemExit("schedule fixture missing schedule_emitter lowering")
if "effect_operation" not in construct_families:
    raise SystemExit("schedule fixture missing effect_operation construct family")
PY
  python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-schedule-check.json" \
    > "$TMP_DIR/generated-schedule-construct-graph.maude"
)
generated_schedule_graph_output="$(maude "$TMP_DIR/generated-schedule-construct-graph.maude")"
printf '%s\n' "$generated_schedule_graph_output"
generated_schedule_graph_no_solution="$(grep -c 'No solution\.' <<<"$generated_schedule_graph_output" || true)"
generated_schedule_graph_solution="$(grep -c '^Solution 1' <<<"$generated_schedule_graph_output" || true)"
generated_schedule_graph_expected_solution="$(cat "$TMP_DIR/generated-schedule-construct-expected.txt")"
if [[ "$generated_schedule_graph_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated schedule construct graph: got $generated_schedule_graph_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_schedule_graph_solution" != "$generated_schedule_graph_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated schedule construct graph: got $generated_schedule_graph_solution, expected $generated_schedule_graph_expected_solution" >&2
  exit 1
fi

echo "== generated Maude from schedule lowered IR"
(
  cd "$ROOT"
  python3 - "$TMP_DIR/generated-schedule-check.json" > "$TMP_DIR/generated-schedule-expected.txt" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
entry = report[0]
graph = entry["construct_graph"]
lowered = entry["lowered_ir_report"]
print(
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3
)
lowering_classes = {node["lowering_class"] for node in graph["nodes"]}
if "schedule_emitter" not in lowering_classes:
    raise SystemExit("schedule fixture missing schedule_emitter lowering")
object_kinds = {obj["object_kind"] for obj in lowered["core_objects"]}
if "schedule" not in object_kinds:
    raise SystemExit("schedule fixture missing lowered schedule core object")
entrypoints = {obj["runtime_entrypoint"] for obj in lowered["core_objects"]}
if "schedule_template" not in entrypoints:
    raise SystemExit("schedule fixture missing schedule_template runtime entrypoint")
PY
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    --root "$ROOT" \
    "$TMP_DIR/generated-schedule-check.json" \
    > "$TMP_DIR/generated-schedule-lowered-ir.maude"
  grep -q 'scheduleEmitterLowering' "$TMP_DIR/generated-schedule-lowered-ir.maude"
  grep -q 'scheduleEntrypoint' "$TMP_DIR/generated-schedule-lowered-ir.maude"
)
generated_schedule_output="$(maude "$TMP_DIR/generated-schedule-lowered-ir.maude")"
printf '%s\n' "$generated_schedule_output"
generated_schedule_no_solution="$(grep -c 'No solution\.' <<<"$generated_schedule_output" || true)"
generated_schedule_solution="$(grep -c '^Solution 1' <<<"$generated_schedule_output" || true)"
generated_schedule_expected_solution="$(cat "$TMP_DIR/generated-schedule-expected.txt")"
if [[ "$generated_schedule_no_solution" != "0" ]]; then
  echo "unexpected No solution count for generated schedule lowered IR: got $generated_schedule_no_solution, expected 0" >&2
  exit 1
fi
if [[ "$generated_schedule_solution" != "$generated_schedule_expected_solution" ]]; then
  echo "unexpected Solution 1 count for generated schedule lowered IR: got $generated_schedule_solution, expected $generated_schedule_expected_solution" >&2
  exit 1
fi

echo "== whip check --model-search includes generated artifact obligations"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- --json check --model-search \
    examples/package-memory.whip \
    > "$TMP_DIR/generated-model-search-check.json"
)
validate_model_search_report \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/generated-model-search-check.json"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- verify-report \
    "$TMP_DIR/generated-model-search-check.json"
)
python3 - "$TMP_DIR/generated-model-search-check.json" "$TMP_DIR/generated-model-search-bad-ledger.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
obligations = report[0]["model_search"]["obligations"]
if not obligations:
    raise SystemExit("generated report did not include model_search obligations to mutate")
obligations[0]["actual"] = (
    "no_solution" if obligations[0]["expected"] == "solution" else "solution"
)
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_model_search_report \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/generated-model-search-bad-ledger.json" \
  2> "$TMP_DIR/generated-model-search-bad-ledger.err"; then
  echo "expected model_search ledger validator to reject mismatched outcomes" >&2
  exit 1
fi
grep -q 'expected/actual mismatch' "$TMP_DIR/generated-model-search-bad-ledger.err"
if (cd "$ROOT" && cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/generated-model-search-bad-ledger.json" \
  2> "$TMP_DIR/generated-model-search-bad-ledger-rust.err"); then
  echo "expected whip verify-report to reject mismatched model_search outcomes" >&2
  exit 1
fi
grep -q 'expected/actual mismatch' "$TMP_DIR/generated-model-search-bad-ledger-rust.err"
python3 - "$TMP_DIR/generated-model-search-check.json" "$TMP_DIR/generated-model-search-bad-artifact-ledger.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
obligations = report[0]["model_search"]["obligations"]
for obligation in obligations:
    if obligation.get("category", "").startswith("artifact."):
        obligation["downstream"] = "stale-artifact-ref"
        break
else:
    raise SystemExit("generated report did not include artifact obligations to mutate")
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_model_search_report \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/generated-model-search-bad-artifact-ledger.json" \
  2> "$TMP_DIR/generated-model-search-bad-artifact-ledger.err"; then
  echo "expected model_search ledger validator to reject stale artifact obligations" >&2
  exit 1
fi
grep -q 'artifact obligation mismatch' "$TMP_DIR/generated-model-search-bad-artifact-ledger.err"
if (cd "$ROOT" && cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/generated-model-search-bad-artifact-ledger.json" \
  2> "$TMP_DIR/generated-model-search-bad-artifact-ledger-rust.err"); then
  echo "expected whip verify-report to reject stale model_search artifact obligations" >&2
  exit 1
fi
grep -q 'model_search artifact obligation mismatch' "$TMP_DIR/generated-model-search-bad-artifact-ledger-rust.err"
python3 - "$TMP_DIR/generated-model-search-check.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
entry = report[0]
graph = entry["construct_graph"]
lowered = entry["lowered_ir_report"]
model_search = entry["model_search"]
platform_catalog = entry["package_contract"]["platform_construct_catalog"]
expected_construct_searches = len(graph["nodes"]) + len(graph["edges"]) + 2
expected_lowered_searches = (
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3
)
expected_platform_searches = len(platform_catalog["lowerings"])
expected_artifact_searches = (
    expected_construct_searches + expected_lowered_searches + expected_platform_searches
)
if model_search.get("status") != "ok":
    raise SystemExit(f"model_search was not ok: {model_search}")
if model_search.get("artifact_searches") != expected_artifact_searches:
    raise SystemExit(
        "unexpected artifact_searches: "
        f"got {model_search.get('artifact_searches')}, expected {expected_artifact_searches}"
    )
if model_search.get("searches") != (
    model_search.get("ir_searches") + model_search.get("artifact_searches")
):
    raise SystemExit(f"model_search totals do not add up: {model_search}")
if model_search.get("artifact_searches", 0) <= 0:
    raise SystemExit(f"model_search did not include artifact obligations: {model_search}")
obligations = model_search.get("obligations")
if not isinstance(obligations, list):
    raise SystemExit(f"model_search missing obligation ledger: {model_search}")
if len(obligations) != model_search.get("searches"):
    raise SystemExit(f"model_search obligation ledger count mismatch: {model_search}")
categories = {}
for obligation in obligations:
    category = obligation.get("category")
    categories[category] = categories.get(category, 0) + 1
    if obligation.get("status") != "ok":
        raise SystemExit(f"model_search obligation was not ok: {obligation}")
    if obligation.get("expected") != obligation.get("actual"):
        raise SystemExit(f"model_search obligation did not match: {obligation}")
    if not isinstance(obligation.get("source_span"), dict):
        raise SystemExit(f"model_search obligation missing source span: {obligation}")
expected_categories = {
    "ir": model_search.get("ir_searches"),
    "artifact.construct_graph": expected_construct_searches,
    "artifact.lowered_ir": expected_lowered_searches,
    "artifact.platform_catalog": expected_platform_searches,
}
if categories != expected_categories:
    raise SystemExit(
        f"model_search obligation categories were {categories}, expected {expected_categories}"
    )
print(
    "validated model_search artifact obligations "
    f"({model_search['artifact_searches']} artifact / {model_search['ir_searches']} IR)"
)
PY

echo "== whip compile --model-search includes generated artifact obligations"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- --json compile --model-search \
    examples/package-memory.whip \
    > "$TMP_DIR/generated-model-search-compile.json"
)
validate_model_search_report \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/generated-model-search-compile.json"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- verify-report \
    "$TMP_DIR/generated-model-search-compile.json"
)
python3 - "$TMP_DIR/generated-model-search-compile.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
graph = report["construct_graph"]
lowered = report["lowered_ir_report"]
model_search = report["model_search"]
platform_catalog = report["package_contract"]["platform_construct_catalog"]
expected_construct_searches = len(graph["nodes"]) + len(graph["edges"]) + 2
expected_lowered_searches = (
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3
)
expected_platform_searches = len(platform_catalog["lowerings"])
expected_artifact_searches = (
    expected_construct_searches + expected_lowered_searches + expected_platform_searches
)
if model_search.get("status") != "ok":
    raise SystemExit(f"compile model_search was not ok: {model_search}")
if model_search.get("artifact_searches") != expected_artifact_searches:
    raise SystemExit(
        "unexpected compile artifact_searches: "
        f"got {model_search.get('artifact_searches')}, expected {expected_artifact_searches}"
    )
if model_search.get("searches") != (
    model_search.get("ir_searches") + model_search.get("artifact_searches")
):
    raise SystemExit(f"compile model_search totals do not add up: {model_search}")
if model_search.get("artifact_searches", 0) <= 0:
    raise SystemExit(f"compile model_search did not include artifact obligations: {model_search}")
obligations = model_search.get("obligations")
if not isinstance(obligations, list):
    raise SystemExit(f"compile model_search missing obligation ledger: {model_search}")
if len(obligations) != model_search.get("searches"):
    raise SystemExit(f"compile model_search obligation ledger count mismatch: {model_search}")
categories = {}
for obligation in obligations:
    category = obligation.get("category")
    categories[category] = categories.get(category, 0) + 1
    if obligation.get("status") != "ok":
        raise SystemExit(f"compile model_search obligation was not ok: {obligation}")
    if obligation.get("expected") != obligation.get("actual"):
        raise SystemExit(f"compile model_search obligation did not match: {obligation}")
    if not isinstance(obligation.get("source_span"), dict):
        raise SystemExit(f"compile model_search obligation missing source span: {obligation}")
expected_categories = {
    "ir": model_search.get("ir_searches"),
    "artifact.construct_graph": expected_construct_searches,
    "artifact.lowered_ir": expected_lowered_searches,
    "artifact.platform_catalog": expected_platform_searches,
}
if categories != expected_categories:
    raise SystemExit(
        "compile model_search obligation categories were "
        f"{categories}, expected {expected_categories}"
    )
print(
    "validated compile model_search artifact obligations "
    f"({model_search['artifact_searches']} artifact / {model_search['ir_searches']} IR)"
)
PY

echo "== whip check --model-search includes core artifact obligations"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- --json check --model-search \
    examples/event-bridge.whip \
    > "$TMP_DIR/generated-event-bridge-model-search-check.json"
)
validate_model_search_report \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/generated-event-bridge-model-search-check.json"
(
  cd "$ROOT"
  cargo run --quiet -p whipplescript -- verify-report \
    "$TMP_DIR/generated-event-bridge-model-search-check.json"
)
python3 - "$TMP_DIR/generated-event-bridge-model-search-check.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
entry = report[0]
graph = entry["construct_graph"]
lowered = entry["lowered_ir_report"]
model_search = entry["model_search"]
platform_catalog = entry["package_contract"]["platform_construct_catalog"]
expected_construct_searches = len(graph["nodes"]) + len(graph["edges"]) + 2
expected_lowered_searches = (
    len(lowered["node_lowerings"])
    + len(lowered["edge_lowerings"])
    + len(lowered["dependency_lowerings"])
    + len(lowered["core_objects"])
    + 3
)
expected_platform_searches = len(platform_catalog["lowerings"])
expected_artifact_searches = (
    expected_construct_searches + expected_lowered_searches + expected_platform_searches
)
lowering_classes = {node["lowering_class"] for node in graph["nodes"]}
if "rule_template" not in lowering_classes:
    raise SystemExit(f"core fixture did not exercise expected lowerings: {lowering_classes}")
if model_search.get("status") != "ok":
    raise SystemExit(f"model_search was not ok: {model_search}")
if model_search.get("artifact_searches") != expected_artifact_searches:
    raise SystemExit(
        "unexpected core artifact_searches: "
        f"got {model_search.get('artifact_searches')}, expected {expected_artifact_searches}"
    )
if model_search.get("searches") != (
    model_search.get("ir_searches") + model_search.get("artifact_searches")
):
    raise SystemExit(f"core model_search totals do not add up: {model_search}")
if model_search.get("artifact_searches", 0) <= 0:
    raise SystemExit(f"core model_search did not include artifact obligations: {model_search}")
obligations = model_search.get("obligations")
if not isinstance(obligations, list):
    raise SystemExit(f"core model_search missing obligation ledger: {model_search}")
if len(obligations) != model_search.get("searches"):
    raise SystemExit(f"core model_search obligation ledger count mismatch: {model_search}")
categories = {}
for obligation in obligations:
    category = obligation.get("category")
    categories[category] = categories.get(category, 0) + 1
    if obligation.get("status") != "ok":
        raise SystemExit(f"core model_search obligation was not ok: {obligation}")
    if obligation.get("expected") != obligation.get("actual"):
        raise SystemExit(f"core model_search obligation did not match: {obligation}")
    if not isinstance(obligation.get("source_span"), dict):
        raise SystemExit(f"core model_search obligation missing source span: {obligation}")
expected_categories = {
    "ir": model_search.get("ir_searches"),
    "artifact.construct_graph": expected_construct_searches,
    "artifact.lowered_ir": expected_lowered_searches,
    "artifact.platform_catalog": expected_platform_searches,
}
if categories != expected_categories:
    raise SystemExit(
        f"core model_search obligation categories were {categories}, expected {expected_categories}"
    )
print(
    "validated core model_search artifact obligations "
    f"({model_search['artifact_searches']} artifact / {model_search['ir_searches']} IR)"
)
PY

if [[ "${WHIPPLESCRIPT_FORMAL_SKIP_TLA:-0}" == "1" ]]; then
  echo "== tla models/tla/*.tla delegated to the dedicated CI gate"
else
  echo "== tla models/tla/*.tla (Apalache typecheck + bounded check)"
  "$ROOT/scripts/check-tla-models.sh"
fi
