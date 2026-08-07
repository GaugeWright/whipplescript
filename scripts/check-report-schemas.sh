#!/usr/bin/env bash
set -Eeuo pipefail

report_schema_error() {
  local status=$?
  trap - ERR
  echo "report schema check failed at line $1: $2" >&2
  exit "$status"
}
trap 'report_schema_error "$LINENO" "$BASH_COMMAND"' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
try:
    import jsonschema  # noqa: F401
except Exception as exc:
    raise SystemExit(
        "python jsonschema package is required; run under `nix develop` or "
        f"install `requirements-dev.txt`: {exc}"
    )
PY

TMP_DIR="$(mktemp -d)"
TMP_STORE="$TMP_DIR/dev.sqlite"
TMP_STREAM_STORE="$TMP_DIR/dev-stream.sqlite"
TMP_ACCEPT_STORE="$TMP_DIR/accept.sqlite"
trap 'rm -rf "$TMP_DIR"' EXIT

cargo run --quiet -p whipplescript -- --json check examples/provider-language-e2e.whip \
  > "$TMP_DIR/check.json"
cargo run --quiet -p whipplescript -- --json compile examples/provider-language-e2e.whip \
  > "$TMP_DIR/compile.json"
cargo run --quiet -p whipplescript -- --json compile examples/event-bridge.whip \
  > "$TMP_DIR/event-bridge-compile.json"
cargo run --quiet -p whipplescript -- --json compile examples/scheduled-escalation.whip \
  > "$TMP_DIR/scheduled-escalation-compile.json"
cargo run --quiet -p whipplescript -- --json compile --model-search \
  examples/event-bridge.whip \
  > "$TMP_DIR/event-bridge-compile-model-search.json"
cargo run --quiet -p whipplescript -- --json compile --model-search \
  examples/scheduled-escalation.whip \
  > "$TMP_DIR/scheduled-escalation-compile-model-search.json"
cargo run --quiet -p whipplescript -- --json compile --model-search \
  examples/provider-language-e2e.whip \
  > "$TMP_DIR/provider-language-compile-model-search.json"
cargo run --quiet -p whipplescript -- --json compile --model-search \
  examples/terminal-output-union.whip \
  > "$TMP_DIR/terminal-output-compile-model-search.json"
cargo run --quiet -p whipplescript -- verify-report --emit artifacts \
  "$TMP_DIR/compile.json" \
  > "$TMP_DIR/compile-verified-artifacts.json"
cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-verified-artifacts.json"
cargo run --quiet -p whipplescript -- verify-report --emit construct-graph \
  "$TMP_DIR/compile.json" \
  > "$TMP_DIR/compile-verified-construct-graph.json"
cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-verified-construct-graph.json" \
  > "$TMP_DIR/compile-verified-construct-graph.summary.txt"
cargo run --quiet -p whipplescript -- verify-report --emit construct-graph \
  "$TMP_DIR/compile-verified-construct-graph.json" \
  > "$TMP_DIR/compile-verified-construct-graph.roundtrip.json"
if cargo run --quiet -p whipplescript -- verify-report --emit lowered-ir \
  "$TMP_DIR/compile-verified-construct-graph.json" \
  > "$TMP_DIR/compile-verified-construct-graph.lowered.err" \
  2>&1; then
  echo "expected verify-report --emit lowered-ir to reject graph-only verified bundles" >&2
  exit 1
fi
grep -q 'requires lowered_ir_report' \
  "$TMP_DIR/compile-verified-construct-graph.lowered.err"
cargo run --quiet -p whipplescript -- verify-report --emit lowered-ir \
  "$TMP_DIR/compile.json" \
  > "$TMP_DIR/compile-verified-lowered-ir.json"
cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-verified-lowered-ir.json"
if cargo run --quiet -p whipplescript -- --json compile \
  --package-lock "$TMP_DIR/missing-package-lock.json" \
  examples/provider-language-e2e.whip \
  > "$TMP_DIR/compile-error.json"; then
  echo "expected compile --json with a missing package lock to fail" >&2
  exit 1
fi
cargo run --quiet -p whipplescript -- --store "$TMP_STORE" --json run \
  examples/provider-language-e2e.whip --provider fixture --until idle \
  > "$TMP_DIR/dev.json"
DEV_INSTANCE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instance_id"])' "$TMP_DIR/dev.json")"
cargo run --quiet -p whipplescript -- --store "$TMP_STORE" --json trace \
  "$DEV_INSTANCE_ID" --check \
  > "$TMP_DIR/trace.json"
cargo run --quiet -p whipplescript -- --store "$TMP_STREAM_STORE" run \
  examples/provider-language-e2e.whip --provider fixture --until idle --stream ndjson \
  > "$TMP_DIR/dev-stream.ndjson"
cargo run --quiet -p whipplescript -- --store "$TMP_ACCEPT_STORE" --json accept \
  examples/provider-language-e2e.accept.json \
  > "$TMP_DIR/acceptance.json"
cargo run --quiet -p whipplescript -- --json package check \
  std/manifests/memory.json \
  > "$TMP_DIR/package-check.json"
PLATFORM_CATALOG_PATH="$TMP_DIR/platform-construct-catalog.json"
cargo run --quiet -p whipplescript -- package catalog \
  > "$PLATFORM_CATALOG_PATH"
unset WHIPPLESCRIPT_PLATFORM_CATALOG_PATH
# Lock mechanics run against the vendor `notes` package: std packages (e.g.
# `std.memory`) ship embedded and can never be lock-provided. Portable locks
# record source.path relative to the lock directory, so the manifest must live
# under that directory.
cp examples/packages/notes.json "$TMP_DIR/notes.json"
cargo run --quiet -p whipplescript -- package lock --output "$TMP_DIR/package-lock.json" \
  "$TMP_DIR/notes.json"
# package-memory.whip resolves `std.memory` from the embedded manifest — no lock.
cargo run --quiet -p whipplescript -- --json check \
  examples/package-memory.whip \
  > "$TMP_DIR/package-memory-check.json"
cargo run --quiet -p whipplescript -- --json check \
  --model-search \
  examples/package-memory.whip \
  > "$TMP_DIR/package-memory-check-model-search.json"
cargo run --quiet -p whipplescript -- package lock \
  examples/packages/notes.json \
  > "$TMP_DIR/package-lock-stdout.json"

# `whip test` report: validate the committed golden example (which exercises the
# v0 harness — given/stub/run and the full expect surface) so its
# `whipplescript.test_report.v0` output stays valid against the schema.
cargo run --quiet -p whipplescript -- --json test \
  examples/tested-agent-turn.whip \
  > "$TMP_DIR/test.json"

construct_graph_to_maude() {
  python3 scripts/construct-graph-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    "$@"
}

lowered_ir_to_maude() {
  python3 scripts/lowered-ir-to-maude.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    "$@"
}

validate_artifact_reports() {
  python3 scripts/validate-artifact-reports.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    "$@"
}

validate_model_search_reports() {
  python3 scripts/validate-model-search-report.py \
    --platform-catalog "$PLATFORM_CATALOG_PATH" \
    "$@"
}

python3 - "$TMP_DIR" <<'PY'
import copy
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator

tmp_dir = Path(sys.argv[1])


def assert_schema_rejects(validator, value, label):
    try:
        validator.validate(value)
    except Exception:
        return
    raise SystemExit(f"{label} unexpectedly validated")


def with_duplicate_derived_fact_input_ref(artifact, label):
    mutated = copy.deepcopy(artifact)
    for fact in mutated.get("derived_facts", []):
        refs = fact.get("input_refs")
        if isinstance(refs, list) and refs:
            refs.append(refs[0])
            return mutated
    raise SystemExit(f"{label} did not contain a derived fact input ref to duplicate")


def with_duplicate_array_member(artifact, collections, label):
    mutated = copy.deepcopy(artifact)
    for collection in collections:
        items = mutated.get(collection)
        if isinstance(items, list) and items:
            items.append(copy.deepcopy(items[0]))
            return mutated
    raise SystemExit(f"{label} did not contain an array member to duplicate")


def with_duplicate_construct_graph_string_ref(artifact, label):
    mutated = copy.deepcopy(artifact)
    fields_by_collection = {
        "nodes": [
            "required_ports",
            "produced_ports",
            "required_capabilities",
            "lowered_effect_capabilities",
            "allowed_core_object_kinds",
            "allowed_runtime_entrypoints",
        ],
        "edges": ["evidence"],
        "effect_dependencies": ["evidence"],
    }
    for collection, fields in fields_by_collection.items():
        for item in mutated.get(collection, []):
            for field in fields:
                refs = item.get(field)
                if isinstance(refs, list) and refs:
                    refs.append(refs[0])
                    return mutated
    raise SystemExit(f"{label} did not contain a construct graph string ref to duplicate")


def with_duplicate_construct_graph_interface(artifact, label):
    mutated = copy.deepcopy(artifact)
    for node in mutated.get("nodes", []):
        for field in ["declared_required_interfaces", "declared_provided_interfaces"]:
            interfaces = node.get(field)
            if isinstance(interfaces, list) and interfaces:
                interfaces.append(copy.deepcopy(interfaces[0]))
                return mutated
    raise SystemExit(f"{label} did not contain a construct graph interface to duplicate")


def with_invalid_construct_graph_output_vocabulary(artifact, label):
    mutated = copy.deepcopy(artifact)
    for node in mutated.get("nodes", []):
        if node.get("allowed_core_object_kinds"):
            node["allowed_core_object_kinds"] = ["effect_object"]
            node["allowed_runtime_entrypoints"] = ["kernel.graph_commit"]
            return mutated
    raise SystemExit(f"{label} did not contain output vocabulary to invalidate")


def first_construct_graph_edge_and_required_port(graph):
    edges = graph.get("edges")
    ports = graph.get("ports")
    if not isinstance(edges, list) or not edges:
        raise SystemExit("construct graph did not contain an edge")
    if not isinstance(ports, list):
        raise SystemExit("construct graph did not contain ports")
    edge = edges[0]
    required_port_id = edge.get("required_port_id")
    for port in ports:
        if port.get("port_id") == required_port_id:
            return edge, port
    raise SystemExit("construct graph edge did not reference a known required port")


def mutate_first_construct_graph(report, mutator, output_path):
    mutated = copy.deepcopy(report)
    if isinstance(mutated, list):
        if not mutated:
            raise SystemExit("report did not contain an entry to mutate")
        entry = mutated[0]
    else:
        entry = mutated
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        raise SystemExit("report did not contain a construct graph")
    mutator(graph)
    output_path.write_text(json.dumps(mutated))


def write_bad_construct_graph_schema_report(report, output_path):
    def mutate(graph):
        graph["schema"] = "whipplescript.not_construct_graph.v0"

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_scalar_metadata_report(report, output_path):
    def mutate(graph):
        edge, port = first_construct_graph_edge_and_required_port(graph)
        port["cardinality"] = "exactly-one"
        edge["order_index"] = 0
        edge["resource_key"] = None

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_duplicate_scalar_resolution_report(report, output_path):
    def mutate(graph):
        edge, port = first_construct_graph_edge_and_required_port(graph)
        port["cardinality"] = "exactly-one"
        duplicate_edge = copy.deepcopy(edge)
        provided_port_id = edge.get("provided_port_id")
        if not isinstance(provided_port_id, str) or not provided_port_id:
            raise SystemExit("construct graph edge did not contain provided_port_id")
        duplicate_port_id = f"{provided_port_id}:duplicate"
        ports = graph.get("ports")
        if not isinstance(ports, list):
            raise SystemExit("construct graph did not contain ports")
        for candidate in ports:
            if isinstance(candidate, dict) and candidate.get("port_id") == provided_port_id:
                duplicate_port = copy.deepcopy(candidate)
                duplicate_port["port_id"] = duplicate_port_id
                ports.append(duplicate_port)
                break
        else:
            raise SystemExit(f"construct graph did not contain port {provided_port_id!r}")
        provider_node_id = duplicate_edge.get("provider_node_id")
        nodes = graph.get("nodes")
        if not isinstance(provider_node_id, str) or not isinstance(nodes, list):
            raise SystemExit("construct graph edge did not contain provider_node_id")
        for node in nodes:
            if isinstance(node, dict) and node.get("node_id") == provider_node_id:
                produced_ports = node.get("produced_ports")
                if not isinstance(produced_ports, list):
                    raise SystemExit(f"construct graph node {provider_node_id!r} had no produced_ports")
                produced_ports.append(duplicate_port_id)
                break
        else:
            raise SystemExit(f"construct graph did not contain node {provider_node_id!r}")
        duplicate_edge["provided_port_id"] = duplicate_port_id
        graph["edges"].append(duplicate_edge)

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_many_missing_order_report(report, output_path):
    def mutate(graph):
        edge, port = first_construct_graph_edge_and_required_port(graph)
        port["cardinality"] = "many"
        sync_declared_interface_cardinality_for_port(graph, port, "many")
        edge["order_index"] = None
        edge["resource_key"] = None

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_named_many_missing_key_report(report, output_path):
    def mutate(graph):
        edge, port = first_construct_graph_edge_and_required_port(graph)
        port["cardinality"] = "named-many"
        sync_declared_interface_cardinality_for_port(graph, port, "named-many")
        edge["order_index"] = 0
        edge["resource_key"] = None

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_unknown_edge_field_report(report, output_path):
    def mutate(graph):
        edges = graph.get("edges")
        if not isinstance(edges, list) or not edges:
            raise SystemExit("construct graph did not contain an edge")
        edge = edges[0]
        if not isinstance(edge, dict):
            raise SystemExit("construct graph edge was not an object")
        edge["unexpected_semantic_field"] = "stale"

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_edge_evidence_type_report(report, output_path):
    def mutate(graph):
        edges = graph.get("edges")
        if not isinstance(edges, list) or not edges:
            raise SystemExit("construct graph did not contain an edge")
        edge = edges[0]
        if not isinstance(edge, dict):
            raise SystemExit("construct graph edge was not an object")
        edge["evidence"] = "not-an-array"

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_source_span_report(report, output_path):
    def mutate(graph):
        nodes = graph.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            raise SystemExit("construct graph did not contain a node")
        node = nodes[0]
        if not isinstance(node, dict) or not isinstance(node.get("source_span"), dict):
            raise SystemExit("construct graph node did not contain a source_span")
        node["source_span"]["start"] = -1

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_derived_fact_span_report(report, output_path):
    def mutate(graph):
        facts = graph.get("derived_facts")
        if not isinstance(facts, list) or not facts:
            raise SystemExit("construct graph did not contain derived facts")
        fact = facts[0]
        if not isinstance(fact, dict) or not isinstance(fact.get("diagnostic_span"), dict):
            raise SystemExit("construct graph derived fact did not contain a diagnostic_span")
        fact["diagnostic_span"]["start"] = -1

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_derived_fact_input_refs_report(report, output_path):
    def mutate(graph):
        facts = graph.get("derived_facts")
        if not isinstance(facts, list) or not facts:
            raise SystemExit("construct graph did not contain derived facts")
        for fact in facts:
            refs = fact.get("input_refs") if isinstance(fact, dict) else None
            if isinstance(refs, list) and refs:
                refs.append(refs[0])
                return
        raise SystemExit("construct graph did not contain a derived fact input ref")

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_derived_fact_metadata_report(report, output_path):
    def mutate(graph):
        facts = graph.get("derived_facts")
        if not isinstance(facts, list) or not facts:
            raise SystemExit("construct graph did not contain derived facts")
        fact = facts[0]
        if not isinstance(fact, dict):
            raise SystemExit("construct graph derived fact was not an object")
        fact["owner_subsystem"] = ""

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_duplicate_derived_fact_report(report, output_path):
    def mutate(graph):
        facts = graph.get("derived_facts")
        if not isinstance(facts, list) or not facts:
            raise SystemExit("construct graph did not contain derived facts")
        for fact in facts:
            if not isinstance(fact, dict):
                continue
            if fact.get("owner_subsystem") == "construct_graph_validator":
                continue
            facts.append(copy.deepcopy(fact))
            return
        raise SystemExit("construct graph did not contain a non-validator derived fact")

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_platform_version_report(report, output_path):
    def mutate(graph):
        graph["platform_version"] = 1

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_node_metadata_report(report, output_path):
    def mutate(graph):
        nodes = graph.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            raise SystemExit("construct graph did not contain a node")
        node = nodes[0]
        if not isinstance(node, dict):
            raise SystemExit("construct graph node was not an object")
        node["metadata"] = "not-an-object"

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_effect_dependency_rule_name_report(report, output_path):
    def mutate(graph):
        dependencies = graph.get("effect_dependencies")
        if not isinstance(dependencies, list) or not dependencies:
            raise SystemExit("construct graph did not contain an effect dependency")
        dependency = dependencies[0]
        if not isinstance(dependency, dict):
            raise SystemExit("construct graph effect dependency was not an object")
        dependency["rule_name"] = 1

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_diagnostic_span_report(report, output_path):
    def mutate(graph):
        graph["diagnostics"] = [
            {
                "code": "construct_graph.test.warning",
                "severity": "warning",
                "refs": {},
                "source_span": {
                    "path": None,
                    "start": -1,
                    "end": 0,
                    "construct": None,
                },
                "message": "malformed diagnostic span fixture",
            }
        ]

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_diagnostic_metadata_report(report, output_path):
    def mutate(graph):
        graph["diagnostics"] = [
            {
                "code": "construct_graph.test.warning",
                "severity": "not-a-severity",
                "refs": {},
                "source_span": {
                    "path": None,
                    "start": 0,
                    "end": 0,
                    "construct": None,
                },
                "message": "malformed diagnostic metadata fixture",
            }
        ]

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_diagnostics_type_report(report, output_path):
    def mutate(graph):
        graph["diagnostics"] = "not-an-array"

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_declared_interface_collection_report(report, field, output_path):
    def mutate(graph):
        nodes = graph.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            raise SystemExit("construct graph did not contain a node")
        node = nodes[0]
        if not isinstance(node, dict):
            raise SystemExit("construct graph node was not an object")
        node[field] = "not-an-array"

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_unknown_output_vocabulary_report(report, output_path):
    mutated = copy.deepcopy(report)
    graph = mutated.get("construct_graph")
    if not isinstance(graph, dict):
        raise SystemExit("report did not contain a construct graph")
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        raise SystemExit("construct graph did not contain nodes")
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if "effect" not in node.get("allowed_core_object_kinds", []):
            continue
        if "effect_graph_template" not in node.get("allowed_runtime_entrypoints", []):
            continue
        node_id = node.get("node_id")
        output_kind = node.get("lowering_output_kind")
        if not isinstance(node_id, str) or not isinstance(output_kind, str):
            raise SystemExit("construct graph output node did not contain ids")
        node["allowed_core_object_kinds"] = ["trace"]
        node["allowed_runtime_entrypoints"] = ["trace_entrypoint"]
        predicate = f"validator.node.output:{node_id}:{output_kind}"
        facts = graph.get("derived_facts")
        if not isinstance(facts, list):
            raise SystemExit("construct graph did not contain derived_facts")
        for fact in facts:
            if (
                isinstance(fact, dict)
                and fact.get("owner_subsystem") == "construct_graph_validator"
                and fact.get("predicate") == predicate
            ):
                fact["input_refs"] = sorted([
                    node_id,
                    output_kind,
                    "trace",
                    "trace_entrypoint",
                ])
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit(f"construct graph did not contain {predicate} fact")
    raise SystemExit("construct graph did not contain an effect output node")


def write_bad_construct_graph_lifecycle_profile_report(report, output_path):
    mutated = copy.deepcopy(report)
    graph = mutated.get("construct_graph")
    if not isinstance(graph, dict):
        raise SystemExit("report did not contain a construct graph")
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        raise SystemExit("construct graph did not contain nodes")
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("lowering_class") not in {"capability_call", "core_effect"}:
            continue
        old_profile = node.get("lifecycle_profile")
        if old_profile not in {"effect_graph", "typed_effect_graph"}:
            continue
        node_id = node.get("node_id")
        if not isinstance(node_id, str):
            raise SystemExit("construct graph lifecycle node did not contain node_id")
        new_profile = "event_projection"
        node["lifecycle_profile"] = new_profile
        predicate = f"validator.node.profile:{node_id}"
        facts = graph.get("derived_facts")
        if not isinstance(facts, list):
            raise SystemExit("construct graph did not contain derived_facts")
        for fact in facts:
            if (
                isinstance(fact, dict)
                and fact.get("owner_subsystem") == "construct_graph_validator"
                and fact.get("predicate") == predicate
            ):
                refs = fact.get("input_refs")
                if not isinstance(refs, list):
                    raise SystemExit(f"{predicate} did not contain input_refs")
                fact["input_refs"] = sorted(
                    new_profile if ref == old_profile else ref for ref in refs
                )
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit(f"construct graph did not contain {predicate} fact")
    raise SystemExit("construct graph did not contain a lifecycle-profile node")


def node_interface_refs(node):
    refs = []
    node_id = node.get("node_id")
    if isinstance(node_id, str) and node_id:
        refs.append(node_id)
    for key in ["required_ports", "produced_ports"]:
        for value in node.get(key, []):
            if isinstance(value, str) and value:
                refs.append(value)
    for key in ["declared_required_interfaces", "declared_provided_interfaces"]:
        for interface in node.get(key, []):
            if not isinstance(interface, dict):
                continue
            for field in ["kind", "name", "type", "phase", "cardinality"]:
                value = interface.get(field)
                if isinstance(value, str) and value:
                    refs.append(value)
    return sorted(set(refs))


def write_bad_construct_graph_missing_lowering_interface_report(report, output_path):
    mutated = copy.deepcopy(report)
    entry = mutated[0] if isinstance(mutated, list) else mutated
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        raise SystemExit("report did not contain a construct graph")
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        raise SystemExit("construct graph did not contain nodes")
    for node in nodes:
        if not isinstance(node, dict) or node.get("lowering_class") != "capability_call":
            continue
        interfaces = node.get("declared_required_interfaces")
        if not isinstance(interfaces, list):
            raise SystemExit("capability_call node did not contain required interfaces")
        kept = [
            interface
            for interface in interfaces
            if not (isinstance(interface, dict) and interface.get("kind") == "Capability")
        ]
        if len(kept) == len(interfaces):
            continue
        node["declared_required_interfaces"] = kept
        node_id = node.get("node_id")
        if not isinstance(node_id, str):
            raise SystemExit("capability_call node did not contain node_id")
        predicate = f"validator.node.interfaces:{node_id}"
        facts = graph.get("derived_facts")
        if not isinstance(facts, list):
            raise SystemExit("construct graph did not contain derived_facts")
        for fact in facts:
            if (
                isinstance(fact, dict)
                and fact.get("owner_subsystem") == "construct_graph_validator"
                and fact.get("predicate") == predicate
            ):
                fact["input_refs"] = node_interface_refs(node)
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit(f"construct graph did not contain {predicate} fact")
    raise SystemExit("construct graph did not contain a capability_call node")


def write_bad_lowered_output_vocabulary_report(report, output_path):
    mutated = copy.deepcopy(report)
    graph = mutated.get("construct_graph")
    if not isinstance(graph, dict):
        raise SystemExit("report did not contain a construct graph")
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        raise SystemExit("construct graph did not contain nodes")
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if "effect" not in node.get("allowed_core_object_kinds", []):
            continue
        if "effect_graph_template" not in node.get("allowed_runtime_entrypoints", []):
            continue
        node_id = node.get("node_id")
        output_kind = node.get("lowering_output_kind")
        if not isinstance(node_id, str) or not isinstance(output_kind, str):
            raise SystemExit("construct graph output node did not contain ids")
        node["allowed_core_object_kinds"] = ["rule"]
        node["allowed_runtime_entrypoints"] = ["rule_template"]
        predicate = f"validator.node.output:{node_id}:{output_kind}"
        facts = graph.get("derived_facts")
        if not isinstance(facts, list):
            raise SystemExit("construct graph did not contain derived_facts")
        for fact in facts:
            if (
                isinstance(fact, dict)
                and fact.get("owner_subsystem") == "construct_graph_validator"
                and fact.get("predicate") == predicate
            ):
                fact["input_refs"] = sorted([node_id, output_kind, "rule", "rule_template"])
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit(f"construct graph did not contain {predicate} fact")
    raise SystemExit("construct graph did not contain an effect output node")


def append_validator_node_interface_ref(graph, node_id, value):
    facts = graph.get("derived_facts")
    if not isinstance(facts, list):
        raise SystemExit("construct graph did not contain derived facts")
    predicate = f"validator.node.interfaces:{node_id}"
    for fact in facts:
        if fact.get("owner_subsystem") != "construct_graph_validator":
            continue
        if fact.get("predicate") != predicate:
            continue
        refs = fact.get("input_refs")
        if not isinstance(refs, list):
            raise SystemExit(f"{predicate} fact did not contain input_refs")
        if value not in refs:
            refs.append(value)
        return
    raise SystemExit(f"construct graph did not contain {predicate} fact")


def sync_declared_interface_cardinality_for_port(graph, port, cardinality):
    node_id = port.get("owner_node_id")
    if not isinstance(node_id, str) or not node_id:
        raise SystemExit("construct graph port did not contain owner_node_id")
    direction = port.get("direction")
    interface_key = {
        "required": "declared_required_interfaces",
        "produced": "declared_provided_interfaces",
    }.get(direction)
    if interface_key is None:
        raise SystemExit(f"construct graph port has unsupported direction {direction!r}")
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        raise SystemExit("construct graph did not contain nodes")
    for node in nodes:
        if node.get("node_id") != node_id:
            continue
        interfaces = node.get(interface_key)
        if not isinstance(interfaces, list):
            raise SystemExit(f"construct graph node {node_id!r} did not contain {interface_key}")
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            if interface.get("kind") != port.get("kind"):
                continue
            name = interface.get("name")
            if isinstance(name, str) and port.get("type") != name and port.get("resource_identity") != name:
                continue
            type_ref = interface.get("type")
            if isinstance(type_ref, str) and port.get("type") != type_ref:
                continue
            interface["cardinality"] = cardinality
            append_validator_node_interface_ref(graph, node_id, cardinality)
            return
        raise SystemExit(f"construct graph node {node_id!r} had no matching interface")
    raise SystemExit(f"construct graph did not contain node {node_id!r}")


def first_construct_graph_node_with_interface(graph, key):
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        raise SystemExit("construct graph did not contain nodes")
    for node in nodes:
        interfaces = node.get(key)
        if isinstance(interfaces, list) and interfaces:
            node_id = node.get("node_id")
            if not isinstance(node_id, str) or not node_id:
                raise SystemExit("construct graph interface node did not contain node_id")
            if not isinstance(interfaces[0], dict):
                raise SystemExit("construct graph interface was not an object")
            return node, interfaces[0]
    raise SystemExit(f"construct graph did not contain {key}")


def write_bad_construct_graph_interface_phase_report(report, output_path):
    def mutate(graph):
        node, interface = first_construct_graph_node_with_interface(
            graph,
            "declared_required_interfaces",
        )
        node_id = node["node_id"]
        interface["phase"] = "runtime"
        append_validator_node_interface_ref(graph, node_id, "runtime")

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_interface_cardinality_report(report, output_path):
    def mutate(graph):
        node, interface = first_construct_graph_node_with_interface(
            graph,
            "declared_provided_interfaces",
        )
        node_id = node["node_id"]
        interface["cardinality"] = "optional-one"
        append_validator_node_interface_ref(graph, node_id, "optional-one")

    mutate_first_construct_graph(report, mutate, output_path)


def write_bad_construct_graph_interface_type_report(report, output_path):
    def mutate(graph):
        _, interface = first_construct_graph_node_with_interface(
            graph,
            "declared_required_interfaces",
        )
        interface["type"] = 1

    mutate_first_construct_graph(report, mutate, output_path)


def write_model_search_stale_construct_evidence_report(report, output_path):
    def mutate(graph):
        facts = graph.get("derived_facts")
        if not isinstance(facts, list):
            raise SystemExit("construct graph did not contain derived facts")
        for fact in facts:
            if fact.get("owner_subsystem") != "construct_graph_validator":
                continue
            refs = fact.get("input_refs")
            if isinstance(refs, list) and refs:
                refs.pop()
                return
        raise SystemExit("construct graph did not contain mutable validator evidence")

    mutate_first_construct_graph(report, mutate, output_path)


def write_model_search_bad_report_schema(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    mutated["schema"] = "whipplescript.not_a_compile_report.v0"
    output_path.write_text(json.dumps(mutated))


def write_model_search_bad_ir_predicate_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    obligations = model_search.get("obligations")
    if not isinstance(obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    for obligation in obligations:
        if isinstance(obligation, dict) and obligation.get("category") == "ir":
            obligation["predicate"] = "not-a-generated-predicate"
            output_path.write_text(json.dumps(mutated))
            return
    raise SystemExit("model-search report fixture did not contain an IR obligation")


def write_model_search_stale_ir_obligations_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    obligations = artifact.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")
    first = obligations[0]
    if not isinstance(first, dict):
        raise SystemExit("IR obligation artifact row must be an object")
    first["upstream"] = "stale-ir-obligation-upstream"
    output_path.write_text(json.dumps(mutated))


def write_model_search_missing_ir_obligation_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    removed = None
    for index, obligation in enumerate(ledger_obligations):
        if isinstance(obligation, dict) and obligation.get("category") == "ir":
            removed = ledger_obligations.pop(index)
            break
    if not isinstance(removed, dict):
        raise SystemExit("model-search report fixture did not contain an IR obligation")
    removed_index = removed.get("index")
    artifact_obligations[:] = [
        obligation
        for obligation in artifact_obligations
        if not (
            isinstance(obligation, dict)
            and obligation.get("index") == removed_index
        )
    ]

    next_index = 1
    for obligation in ledger_obligations:
        if isinstance(obligation, dict) and obligation.get("category") == "ir":
            obligation["index"] = next_index
            next_index += 1
    for next_index, obligation in enumerate(artifact_obligations, start=1):
        if isinstance(obligation, dict):
            obligation["index"] = next_index

    for field in ["searches", "ir_searches"]:
        value = model_search.get(field)
        if not isinstance(value, int) or value <= 0:
            raise SystemExit(f"model_search.{field} was not decrementable")
        model_search[field] = value - 1
    outcome_field = {
        "solution": "solutions",
        "no_solution": "no_solutions",
    }.get(removed.get("actual"))
    if outcome_field is None:
        raise SystemExit("removed IR obligation had invalid outcome")
    value = model_search.get(outcome_field)
    if not isinstance(value, int) or value <= 0:
        raise SystemExit(f"model_search.{outcome_field} was not decrementable")
    model_search[outcome_field] = value - 1
    output_path.write_text(json.dumps(mutated))


def write_model_search_wrong_ir_predicate_counts_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    ir_ledger = [
        (position, obligation)
        for position, obligation in enumerate(ledger_obligations)
        if isinstance(obligation, dict) and obligation.get("category") == "ir"
    ]
    artifact_by_index = {
        obligation.get("index"): (position, obligation)
        for position, obligation in enumerate(artifact_obligations)
        if isinstance(obligation, dict)
    }

    for source_position, source in ir_ledger:
        source_index = source.get("index")
        if source_index not in artifact_by_index:
            continue
        for target_position, target in ir_ledger:
            target_index = target.get("index")
            if source_position == target_position:
                continue
            if target_index not in artifact_by_index:
                continue
            if source.get("predicate") == target.get("predicate"):
                continue
            if source.get("actual") != target.get("actual"):
                continue
            replacement = copy.deepcopy(source)
            replacement["index"] = target_index
            ledger_obligations[target_position] = replacement

            _, source_artifact = artifact_by_index[source_index]
            target_artifact_position, _ = artifact_by_index[target_index]
            artifact_replacement = copy.deepcopy(source_artifact)
            artifact_replacement["index"] = target_index
            artifact_obligations[target_artifact_position] = artifact_replacement
            output_path.write_text(json.dumps(mutated))
            return
    raise SystemExit(
        "model-search report fixture did not contain replaceable IR obligations"
    )


def write_model_search_wrong_ir_endpoint_counts_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    ir_ledger = [
        (position, obligation)
        for position, obligation in enumerate(ledger_obligations)
        if isinstance(obligation, dict) and obligation.get("category") == "ir"
    ]
    artifact_by_index = {
        obligation.get("index"): (position, obligation)
        for position, obligation in enumerate(artifact_obligations)
        if isinstance(obligation, dict)
    }
    outcome_fields = {
        "solution": "solutions",
        "no_solution": "no_solutions",
    }

    for source_position, source in ir_ledger:
        source_index = source.get("index")
        if source_index not in artifact_by_index:
            continue
        for target_position, target in ir_ledger:
            target_index = target.get("index")
            if source_position == target_position:
                continue
            if target_index not in artifact_by_index:
                continue
            if source.get("predicate") != target.get("predicate"):
                continue
            if (
                source.get("upstream"),
                source.get("downstream"),
            ) == (
                target.get("upstream"),
                target.get("downstream"),
            ):
                continue

            source_outcome = source.get("actual")
            target_outcome = target.get("actual")
            if source_outcome not in outcome_fields or target_outcome not in outcome_fields:
                continue
            if source_outcome != target_outcome:
                source_field = outcome_fields[source_outcome]
                target_field = outcome_fields[target_outcome]
                source_value = model_search.get(source_field)
                target_value = model_search.get(target_field)
                if (
                    not isinstance(source_value, int)
                    or not isinstance(target_value, int)
                    or target_value <= 0
                ):
                    continue
                model_search[source_field] = source_value + 1
                model_search[target_field] = target_value - 1

            replacement = copy.deepcopy(source)
            replacement["index"] = target_index
            ledger_obligations[target_position] = replacement

            _, source_artifact = artifact_by_index[source_index]
            target_artifact_position, _ = artifact_by_index[target_index]
            artifact_replacement = copy.deepcopy(source_artifact)
            artifact_replacement["index"] = target_index
            artifact_obligations[target_artifact_position] = artifact_replacement
            output_path.write_text(json.dumps(mutated))
            return
    raise SystemExit(
        "model-search report fixture did not contain same-predicate replaceable IR obligations"
    )


def write_model_search_wrong_ir_outcome_counts_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")
    outcome_fields = {
        "solution": "solutions",
        "no_solution": "no_solutions",
    }

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        old_outcome = ledger_obligation.get("actual")
        if old_outcome not in outcome_fields:
            continue
        new_outcome = "solution" if old_outcome == "no_solution" else "no_solution"
        old_field = outcome_fields[old_outcome]
        new_field = outcome_fields[new_outcome]
        old_value = model_search.get(old_field)
        new_value = model_search.get(new_field)
        if not isinstance(old_value, int) or not isinstance(new_value, int) or old_value <= 0:
            continue

        ledger_obligation["actual"] = new_outcome
        ledger_obligation["expected"] = new_outcome
        model_search[old_field] = old_value - 1
        model_search[new_field] = new_value + 1

        obligation_index = ledger_obligation.get("index")
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["expected"] = new_outcome
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit("IR obligation artifact row did not match ledger index")
    raise SystemExit("model-search report fixture did not contain a flippable IR obligation")


def write_model_search_wrong_ir_sequence_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    ir_ledger = [
        (position, obligation)
        for position, obligation in enumerate(ledger_obligations)
        if isinstance(obligation, dict) and obligation.get("category") == "ir"
    ]
    if len(ir_ledger) < 2:
        raise SystemExit("model-search report fixture did not contain two IR obligations")
    first_position, first = ir_ledger[0]
    second_position, second = ir_ledger[1]
    first_index = first.get("index")
    second_index = second.get("index")

    artifact_by_index = {
        obligation.get("index"): (position, obligation)
        for position, obligation in enumerate(artifact_obligations)
        if isinstance(obligation, dict)
    }
    if first_index not in artifact_by_index or second_index not in artifact_by_index:
        raise SystemExit("IR obligation artifact rows did not match ledger indexes")

    first_replacement = copy.deepcopy(second)
    first_replacement["index"] = first_index
    second_replacement = copy.deepcopy(first)
    second_replacement["index"] = second_index
    ledger_obligations[first_position] = first_replacement
    ledger_obligations[second_position] = second_replacement

    first_artifact_position, first_artifact = artifact_by_index[first_index]
    second_artifact_position, second_artifact = artifact_by_index[second_index]
    first_artifact_replacement = copy.deepcopy(second_artifact)
    first_artifact_replacement["index"] = first_index
    second_artifact_replacement = copy.deepcopy(first_artifact)
    second_artifact_replacement["index"] = second_index
    artifact_obligations[first_artifact_position] = first_artifact_replacement
    artifact_obligations[second_artifact_position] = second_artifact_replacement
    output_path.write_text(json.dumps(mutated))


def write_model_search_wrong_ir_description_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        obligation_index = ledger_obligation.get("index")
        ledger_obligation["description"] = "stale generated IR description"
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["description"] = "stale generated IR description"
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit("IR obligation artifact row did not match ledger index")
    raise SystemExit("model-search report fixture did not contain an IR obligation")


def write_model_search_wrong_dependency_source_span_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("predicate") not in {"succeeds", "fails", "completes"}:
            continue
        obligation_index = ledger_obligation.get("index")
        old_span = ledger_obligation.get("source_span")
        stale_span = {"start": 0, "end": 0}
        if isinstance(old_span, dict) and old_span.get("start") == 0 and old_span.get("end") == 0:
            stale_span = {"start": 1, "end": 1}
        ledger_obligation["source_span"] = stale_span
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["source_span"] = stale_span
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit("IR obligation artifact row did not match ledger index")
    raise SystemExit("model-search report fixture did not contain a dependency IR obligation")


def write_model_search_wrong_handoff_source_span_report(report, output_path):
    mutated = copy.deepcopy(report)
    if isinstance(mutated, list):
        if not mutated:
            raise SystemExit("model-search report fixture must contain a check report entry")
        entry = mutated[0]
    else:
        entry = mutated
    if not isinstance(entry, dict):
        raise SystemExit("model-search report fixture must contain a report object")
    model_search = entry.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict):
            continue
        if ledger_obligation.get("category") != "artifact.lowered_ir":
            continue
        if ledger_obligation.get("predicate") != "handoffObjectOk":
            continue
        old_span = ledger_obligation.get("source_span")
        stale_span = {"start": 0, "end": 0}
        if isinstance(old_span, dict) and old_span.get("start") == 0 and old_span.get("end") == 0:
            stale_span = {"start": 1, "end": 1}
        ledger_obligation["source_span"] = stale_span
        output_path.write_text(json.dumps(mutated))
        return
    raise SystemExit("model-search report fixture did not contain a handoff artifact obligation")


def sync_artifact_model_search_source_span(entry, category, obligation_index, source_span):
    artifact = entry.get("artifact_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing artifact_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing artifact obligation rows")
    for artifact_obligation in artifact_obligations:
        if (
            isinstance(artifact_obligation, dict)
            and artifact_obligation.get("category") == category
            and artifact_obligation.get("index") == obligation_index
        ):
            artifact_obligation["source_span"] = copy.deepcopy(source_span)
            return
    raise SystemExit("artifact obligation artifact row did not match ledger index")


def write_model_search_wrong_dependency_source_span_with_graph_report(report, output_path):
    mutated = copy.deepcopy(report)
    if isinstance(mutated, list):
        if not mutated:
            raise SystemExit("model-search report fixture must contain a check report entry")
        entry = mutated[0]
    else:
        entry = mutated
    if not isinstance(entry, dict):
        raise SystemExit("model-search report fixture must contain a report object")
    model_search = entry.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = entry.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")
    construct_graph = entry.get("construct_graph")
    if not isinstance(construct_graph, dict):
        raise SystemExit("model-search report fixture missing construct_graph")
    effect_dependencies = construct_graph.get("effect_dependencies")
    if not isinstance(effect_dependencies, list):
        raise SystemExit("model-search report fixture missing construct_graph.effect_dependencies")
    derived_facts = construct_graph.get("derived_facts")
    if not isinstance(derived_facts, list):
        raise SystemExit("model-search report fixture missing construct_graph.derived_facts")

    target_upstream = None
    target_predicate = None
    target_downstream = None
    stale_span = None
    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("predicate") not in {"succeeds", "fails", "completes"}:
            continue
        target_upstream = ledger_obligation.get("upstream")
        target_predicate = ledger_obligation.get("predicate")
        target_downstream = ledger_obligation.get("downstream")
        old_span = ledger_obligation.get("source_span")
        stale_span = {"start": 0, "end": 0}
        if isinstance(old_span, dict) and old_span.get("start") == 0 and old_span.get("end") == 0:
            stale_span = {"start": 1, "end": 1}
        break
    if target_upstream is None or target_predicate is None or target_downstream is None or stale_span is None:
        raise SystemExit("model-search report fixture did not contain a dependency IR obligation")

    dependency_matches = []
    for dependency in effect_dependencies:
        if not isinstance(dependency, dict):
            continue
        if dependency.get("predicate") != target_predicate:
            continue
        upstream_node_id = dependency.get("upstream_node_id")
        downstream_node_id = dependency.get("downstream_node_id")
        if not (
            isinstance(upstream_node_id, str)
            and upstream_node_id.endswith(f":{target_upstream}")
            and isinstance(downstream_node_id, str)
            and downstream_node_id.endswith(f":{target_downstream}")
        ):
            continue
        dependency_matches.append(dependency)
    if len(dependency_matches) != 1:
        raise SystemExit("model-search report fixture did not contain a unique dependency source")
    graph_span = dependency_matches[0].get("source_span")
    if not isinstance(graph_span, dict):
        raise SystemExit("dependency source did not contain source_span")
    graph_span["start"] = stale_span["start"]
    graph_span["end"] = stale_span["end"]
    dependency_ref = dependency_matches[0].get("dependency_ref")
    for fact in derived_facts:
        if not isinstance(fact, dict):
            continue
        refs = fact.get("input_refs")
        if not isinstance(refs, list) or dependency_ref not in refs:
            continue
        diagnostic_span = fact.get("diagnostic_span")
        if not isinstance(diagnostic_span, dict):
            continue
        if diagnostic_span.get("construct") == "after":
            diagnostic_span["start"] = stale_span["start"]
            diagnostic_span["end"] = stale_span["end"]

    mutated_indexes = set()
    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("upstream") != target_upstream:
            continue
        if ledger_obligation.get("predicate") != target_predicate:
            continue
        if ledger_obligation.get("downstream") != target_downstream:
            continue
        obligation_index = ledger_obligation.get("index")
        ledger_obligation["source_span"] = stale_span
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["source_span"] = stale_span
                mutated_indexes.add(obligation_index)
                break
        else:
            raise SystemExit("IR obligation artifact row did not match ledger index")
    if not mutated_indexes:
        raise SystemExit("model-search report fixture did not mutate a dependency IR obligation")
    mutated_lowered_artifact = False
    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict):
            continue
        if ledger_obligation.get("category") != "artifact.lowered_ir":
            continue
        if ledger_obligation.get("predicate") != "dependencyLoweringPreserved":
            continue
        if ledger_obligation.get("downstream") != dependency_ref:
            continue
        obligation_index = ledger_obligation.get("index")
        ledger_obligation["source_span"] = stale_span
        sync_artifact_model_search_source_span(
            entry,
            "artifact.lowered_ir",
            obligation_index,
            stale_span,
        )
        mutated_lowered_artifact = True
    if not mutated_lowered_artifact:
        raise SystemExit("model-search report fixture did not mutate lowered dependency artifact obligation")
    output_path.write_text(json.dumps(mutated))


def write_model_search_wrong_assertion_source_span_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("predicate") != "assertion-read-only":
            continue
        obligation_index = ledger_obligation.get("index")
        old_span = ledger_obligation.get("source_span")
        stale_span = {"start": 0, "end": 0}
        if isinstance(old_span, dict) and old_span.get("start") == 0 and old_span.get("end") == 0:
            stale_span = {"start": 1, "end": 1}
        ledger_obligation["source_span"] = stale_span
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["source_span"] = stale_span
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit("IR obligation artifact row did not match ledger index")
    raise SystemExit("model-search report fixture did not contain an assertion IR obligation")


def write_model_search_wrong_revision_source_span_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("predicate") not in {
            "revision-active-rule",
            "revision-stale-rule",
            "revision-effect-attribution",
        }:
            continue
        obligation_index = ledger_obligation.get("index")
        old_span = ledger_obligation.get("source_span")
        stale_span = {"start": 0, "end": 0}
        if isinstance(old_span, dict) and old_span.get("start") == 0 and old_span.get("end") == 0:
            stale_span = {"start": 1, "end": 1}
        ledger_obligation["source_span"] = stale_span
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["source_span"] = stale_span
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit("IR obligation artifact row did not match ledger index")
    raise SystemExit("model-search report fixture did not contain a revision IR obligation")


def write_model_search_wrong_guard_source_span_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("predicate") not in {"guard-true", "guard-false", "guard-error"}:
            continue
        obligation_index = ledger_obligation.get("index")
        old_span = ledger_obligation.get("source_span")
        stale_span = {"start": 0, "end": 0}
        if isinstance(old_span, dict) and old_span.get("start") == 0 and old_span.get("end") == 0:
            stale_span = {"start": 1, "end": 1}
        ledger_obligation["source_span"] = stale_span
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["source_span"] = stale_span
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit("IR obligation artifact row did not match ledger index")
    raise SystemExit("model-search report fixture did not contain a guard IR obligation")


def write_model_search_wrong_guard_source_span_with_anchor_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")
    construct_graph = mutated.get("construct_graph")
    if not isinstance(construct_graph, dict):
        raise SystemExit("model-search report fixture missing construct_graph")
    derived_facts = construct_graph.get("derived_facts")
    if not isinstance(derived_facts, list):
        raise SystemExit("model-search report fixture missing construct_graph.derived_facts")

    target_upstream = None
    stale_span = None
    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("predicate") not in {"guard-true", "guard-false", "guard-error"}:
            continue
        target_upstream = ledger_obligation.get("upstream")
        old_span = ledger_obligation.get("source_span")
        stale_span = {"start": 0, "end": 0}
        if isinstance(old_span, dict) and old_span.get("start") == 0 and old_span.get("end") == 0:
            stale_span = {"start": 1, "end": 1}
        break
    if target_upstream is None or stale_span is None:
        raise SystemExit("model-search report fixture did not contain a guard IR obligation")

    rule_ref = f"rule:{target_upstream}"
    anchor_matches = []
    for fact in derived_facts:
        if not isinstance(fact, dict):
            continue
        predicate = fact.get("predicate")
        refs = fact.get("input_refs")
        if (
            fact.get("owner_subsystem") == "compiler"
            and isinstance(predicate, str)
            and predicate.startswith("model_search.guard_source:")
            and isinstance(refs, list)
            and rule_ref in refs
            and "kind:guard" in refs
        ):
            anchor_matches.append(fact)
    if len(anchor_matches) != 1:
        raise SystemExit("model-search report fixture did not contain a unique guard source anchor")
    diagnostic_span = anchor_matches[0].get("diagnostic_span")
    if not isinstance(diagnostic_span, dict):
        raise SystemExit("guard source anchor did not contain diagnostic_span")
    diagnostic_span["start"] = stale_span["start"]
    diagnostic_span["end"] = stale_span["end"]

    mutated_indexes = set()
    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("upstream") != target_upstream:
            continue
        if ledger_obligation.get("predicate") not in {"guard-true", "guard-false", "guard-error"}:
            continue
        obligation_index = ledger_obligation.get("index")
        ledger_obligation["source_span"] = stale_span
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["source_span"] = stale_span
                mutated_indexes.add(obligation_index)
                break
        else:
            raise SystemExit("IR obligation artifact row did not match ledger index")
    if not mutated_indexes:
        raise SystemExit("model-search report fixture did not mutate a guard IR obligation")
    output_path.write_text(json.dumps(mutated))


def write_model_search_wrong_terminal_source_span_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        if ledger_obligation.get("predicate") not in {
            "terminal-branch-match",
            "terminal-branch-miss",
            "terminal-branch-guard-false",
            "terminal-exhaustive-miss",
        }:
            continue
        obligation_index = ledger_obligation.get("index")
        old_span = ledger_obligation.get("source_span")
        stale_span = {"start": 0, "end": 0}
        if isinstance(old_span, dict) and old_span.get("start") == 0 and old_span.get("end") == 0:
            stale_span = {"start": 1, "end": 1}
        ledger_obligation["source_span"] = stale_span
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["source_span"] = stale_span
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit("IR obligation artifact row did not match ledger index")
    raise SystemExit("model-search report fixture did not contain a terminal branch IR obligation")


def write_model_search_unsupported_ir_obligation_report(report, output_path):
    mutated = copy.deepcopy(report)
    if not isinstance(mutated, dict):
        raise SystemExit("model-search report fixture must be a compile report object")
    model_search = mutated.get("model_search")
    if not isinstance(model_search, dict):
        raise SystemExit("model-search report fixture missing model_search object")
    ledger_obligations = model_search.get("obligations")
    if not isinstance(ledger_obligations, list):
        raise SystemExit("model-search report fixture missing obligations array")
    artifact = mutated.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        raise SystemExit("model-search report fixture missing ir_model_search_obligations")
    artifact_obligations = artifact.get("obligations")
    if not isinstance(artifact_obligations, list):
        raise SystemExit("model-search report fixture missing IR obligation artifact rows")

    for ledger_obligation in ledger_obligations:
        if not isinstance(ledger_obligation, dict) or ledger_obligation.get("category") != "ir":
            continue
        obligation_index = ledger_obligation.get("index")
        stale_upstream = "unsupported-ir-obligation-upstream"
        ledger_obligation["upstream"] = stale_upstream
        for artifact_obligation in artifact_obligations:
            if (
                isinstance(artifact_obligation, dict)
                and artifact_obligation.get("index") == obligation_index
            ):
                artifact_obligation["upstream"] = stale_upstream
                output_path.write_text(json.dumps(mutated))
                return
        raise SystemExit("IR obligation artifact row did not match ledger index")
    raise SystemExit("model-search report fixture did not contain an IR obligation")


def with_duplicate_lowered_ir_witness_ref(artifact, label):
    mutated = copy.deepcopy(artifact)
    fields_by_collection = {
        "node_lowerings": [
            "produced_core_object_refs",
            "preserved_source_span_refs",
            "preserved_resource_refs",
            "preserved_capability_refs",
            "preserved_version_refs",
            "preserved_cardinality_refs",
            "preserved_provenance_refs",
            "preserved_terminal_binding_refs",
        ],
        "edge_lowerings": [
            "produced_core_object_refs",
            "preserved_type_refs",
            "preserved_resource_refs",
            "preserved_capability_refs",
            "preserved_version_refs",
            "preserved_span_refs",
            "preserved_cardinality_refs",
            "preserved_provenance_refs",
        ],
        "dependency_lowerings": [
            "produced_core_object_refs",
            "preserved_effect_refs",
            "preserved_span_refs",
            "preserved_provenance_refs",
        ],
    }
    for collection, fields in fields_by_collection.items():
        for lowering in mutated.get(collection, []):
            for field in fields:
                refs = lowering.get(field)
                if isinstance(refs, list) and refs:
                    refs.append(refs[0])
                    return mutated
    raise SystemExit(f"{label} did not contain a lowered IR witness ref to duplicate")


def with_duplicate_lowered_ir_core_object_metadata_ref(artifact, label):
    mutated = copy.deepcopy(artifact)
    core_objects = mutated.get("core_objects")
    if not isinstance(core_objects, list) or not core_objects:
        raise SystemExit(f"{label} did not contain core objects")
    core_object = core_objects[0]
    if not isinstance(core_object, dict):
        raise SystemExit(f"{label} first core object was not an object")
    core_object["resource_refs"] = ["resource:db", "resource:db"]
    return mutated


def with_duplicate_package_manifest_string_array(manifest, label):
    mutated = copy.deepcopy(manifest)
    for library in mutated.get("libraries", []):
        for field in ["effect_contracts", "effects"]:
            for contract in library.get(field, []):
                for array_field in [
                    "source_forms",
                    "required_capabilities",
                    "provider_kinds",
                    "projected_facts",
                ]:
                    values = contract.get(array_field)
                    if isinstance(values, list) and values:
                        values.append(values[0])
                        return mutated
    for profile in mutated.get("profiles", []):
        values = profile.get("allowed_capabilities")
        if isinstance(values, list) and values:
            values.append(values[0])
            return mutated
    raise SystemExit(f"{label} did not contain a package manifest string array to duplicate")


def fail(message):
    raise SystemExit(message)


def assert_reporting_schema_index_complete(schema_paths):
    reporting = Path("spec/reporting.md").read_text()
    missing = [
        str(path)
        for path in schema_paths
        if f"report-schemas/{path.name}" not in reporting
    ]
    if missing:
        fail(
            "spec/reporting.md schema index is missing: "
            + ", ".join(missing)
        )


def sorted_keys(value):
    return sorted(value.keys())


def required_set(schema_fragment):
    return set(schema_fragment.get("required", []))


def resolve_local_ref(schema, value):
    if not isinstance(value, dict):
        return value
    ref = value.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
        return value
    def_name = ref.removeprefix("#/$defs/")
    resolved = copy.deepcopy(schema.get("$defs", {}).get(def_name, {}))
    for key, item in value.items():
        if key != "$ref":
            resolved[key] = item
    return resolved


def assert_array_contract(schema, property_schema, label, require_unique):
    resolved = resolve_local_ref(schema, property_schema)
    if resolved.get("type") != "array":
        fail(f"{label} is not an array schema")
    if bool(resolved.get("uniqueItems", False)) != require_unique:
        fail(f"{label} uniqueItems drifted")
    if "items" not in resolved:
        fail(f"{label} is missing items")


def assert_embedded_artifact_schema_aligned(report_schema, report_name, artifact_schema, def_name, array_fields):
    embedded = report_schema.get("$defs", {}).get(def_name)
    if not isinstance(embedded, dict):
        fail(f"{report_name} missing embedded {def_name} schema")
    if required_set(embedded) != required_set(artifact_schema):
        fail(
            f"{report_name} embedded {def_name} required fields drifted: "
            f"{sorted(required_set(embedded))!r} != {sorted(required_set(artifact_schema))!r}"
        )
    embedded_properties = embedded.get("properties", {})
    artifact_properties = artifact_schema.get("properties", {})
    if set(embedded_properties) != set(artifact_properties):
        fail(
            f"{report_name} embedded {def_name} properties drifted: "
            f"{sorted_keys(embedded_properties)!r} != {sorted_keys(artifact_properties)!r}"
        )

    embedded_const = embedded_properties.get("schema", {}).get("const")
    artifact_const = artifact_properties.get("schema", {}).get("const")
    if embedded_const != artifact_const:
        fail(
            f"{report_name} embedded {def_name} schema const drifted: "
            f"{embedded_const!r} != {artifact_const!r}"
        )

    for field in sorted(array_fields):
        assert_array_contract(
            artifact_schema,
            artifact_properties.get(field),
            f"standalone {def_name}.{field}",
            True,
        )
        assert_array_contract(
            report_schema,
            embedded_properties.get(field),
            f"{report_name} embedded {def_name}.{field}",
            True,
        )

    assert_array_contract(
        artifact_schema,
        artifact_properties.get("derived_facts"),
        f"standalone {def_name}.derived_facts",
        True,
    )
    assert_array_contract(
        report_schema,
        embedded_properties.get("derived_facts"),
        f"{report_name} embedded {def_name}.derived_facts",
        True,
    )
    assert_array_contract(
        artifact_schema,
        artifact_properties.get("diagnostics"),
        f"standalone {def_name}.diagnostics",
        False,
    )
    assert_array_contract(
        report_schema,
        embedded_properties.get("diagnostics"),
        f"{report_name} embedded {def_name}.diagnostics",
        False,
    )


def assert_embedded_derived_fact_aligned(report_schema, report_name, artifact_schema, artifact_name):
    embedded = report_schema.get("$defs", {}).get("derived_fact")
    standalone = artifact_schema.get("$defs", {}).get("derived_fact")
    if not isinstance(embedded, dict) or not isinstance(standalone, dict):
        fail(f"{report_name} or {artifact_name} missing derived_fact schema")
    if required_set(embedded) != required_set(standalone):
        fail(f"{report_name} derived_fact required fields drifted from {artifact_name}")
    if set(embedded.get("properties", {})) != set(standalone.get("properties", {})):
        fail(f"{report_name} derived_fact properties drifted from {artifact_name}")

    embedded_refs = embedded["properties"].get("input_refs")
    standalone_refs = standalone["properties"].get("input_refs")
    assert_array_contract(report_schema, embedded_refs, f"{report_name}.derived_fact.input_refs", True)
    assert_array_contract(artifact_schema, standalone_refs, f"{artifact_name}.derived_fact.input_refs", True)


def assert_embedded_artifact_schemas_match(first_schema, first_name, second_schema, second_name):
    for def_name in [
        "package_contract",
        "construct_graph",
        "lowered_ir_report",
        "derived_fact",
        "string_array",
        "platform_construct_catalog",
        "platform_construct_family",
        "platform_construct_lowering",
    ]:
        if first_schema.get("$defs", {}).get(def_name) != second_schema.get("$defs", {}).get(def_name):
            fail(f"{first_name} and {second_name} embedded {def_name} schemas drifted")


def assert_embedded_package_contract_catalog_aligned(report_schema, report_name, package_contract_schema):
    embedded_contract = report_schema.get("$defs", {}).get("package_contract", {})
    embedded_catalog_ref = (
        embedded_contract
        .get("properties", {})
        .get("platform_construct_catalog", {})
        .get("$ref")
    )
    if embedded_catalog_ref != "#/$defs/platform_construct_catalog":
        fail(
            f"{report_name} embedded package_contract.platform_construct_catalog "
            f"must use #/$defs/platform_construct_catalog, got {embedded_catalog_ref!r}"
        )
    embedded_defs = report_schema.get("$defs", {})
    standalone_catalog = package_contract_schema.get("properties", {}).get("platform_construct_catalog")
    if embedded_defs.get("platform_construct_catalog") != standalone_catalog:
        fail(f"{report_name} embedded platform_construct_catalog schema drifted from package_contract_v0")
    for def_name in ["string_array", "platform_construct_family", "platform_construct_lowering"]:
        if embedded_defs.get(def_name) != package_contract_schema.get("$defs", {}).get(def_name):
            fail(f"{report_name} embedded {def_name} schema drifted from package_contract_v0")


def assert_embedded_platform_catalog_aligned(embedding_schema, embedding_name, platform_catalog_schema):
    embedded_defs = embedding_schema.get("$defs", {})
    standalone_catalog = {
        key: value
        for key, value in platform_catalog_schema.items()
        if key not in ["$schema", "$id", "title", "$defs"]
    }
    if embedded_defs.get("platform_construct_catalog") != standalone_catalog:
        fail(f"{embedding_name} embedded platform_construct_catalog schema drifted from standalone platform catalog schema")
    for def_name in ["string_array", "platform_construct_family", "platform_construct_lowering"]:
        if embedded_defs.get(def_name) != platform_catalog_schema.get("$defs", {}).get(def_name):
            fail(f"{embedding_name} embedded {def_name} schema drifted from standalone platform catalog schema")


def standalone_schema_body(schema):
    return {
        key: value
        for key, value in schema.items()
        if key not in ["$schema", "$id", "title", "$defs"]
    }


def assert_embedded_ir_model_search_obligations_aligned(
    report_schema,
    report_name,
    ir_obligations_schema,
):
    embedded_defs = report_schema.get("$defs", {})
    embedded = embedded_defs.get("ir_model_search_obligations")
    standalone = standalone_schema_body(ir_obligations_schema)
    if embedded != standalone:
        fail(
            f"{report_name} embedded ir_model_search_obligations schema "
            "drifted from standalone IR model-search obligations schema"
        )
    for def_name in ["stable_digest", "span", "ir_model_search_obligation"]:
        if embedded_defs.get(def_name) != ir_obligations_schema.get("$defs", {}).get(def_name):
            fail(
                f"{report_name} embedded {def_name} schema drifted from "
                "standalone IR model-search obligations schema"
            )


def assert_verified_bundle_schema_uses_embedded_artifacts(bundle_schema):
    entry = bundle_schema.get("$defs", {}).get("entry", {})
    properties = entry.get("properties", {})
    expected_refs = {
        "contract_registry": "#/$defs/contract_registry",
        "package_contract": "#/$defs/package_contract",
        "construct_graph": "#/$defs/construct_graph",
        "lowered_ir_report": "#/$defs/lowered_ir_report",
    }
    for field, expected_ref in expected_refs.items():
        actual_ref = properties.get(field, {}).get("$ref")
        if actual_ref != expected_ref:
            fail(
                f"verified_artifacts_v0 entry.{field} must use {expected_ref}, "
                f"got {actual_ref!r}"
            )


schema_paths = sorted(Path("spec/report-schemas").glob("*.schema.json"))
assert_reporting_schema_index_complete(schema_paths)
for schema_path in schema_paths:
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    print(f"validated schema draft {schema_path.name}")

check_report_schema = json.loads(Path("spec/report-schemas/check_report_v0.schema.json").read_text())
compile_report_schema = json.loads(Path("spec/report-schemas/compile_report_v0.schema.json").read_text())
verified_artifacts_schema = json.loads(Path("spec/report-schemas/verified_artifacts_v0.schema.json").read_text())
construct_graph_schema = json.loads(Path("spec/report-schemas/construct_graph_v0.schema.json").read_text())
lowered_ir_schema = json.loads(Path("spec/report-schemas/lowered_ir_report_v0.schema.json").read_text())
package_contract_schema = json.loads(Path("spec/report-schemas/package_contract_v0.schema.json").read_text())
package_check_schema = json.loads(Path("spec/report-schemas/package_check_v0.schema.json").read_text())
platform_catalog_schema = json.loads(Path("spec/report-schemas/platform_construct_catalog_v0.schema.json").read_text())
ir_model_search_obligations_schema = json.loads(Path("spec/report-schemas/ir_model_search_obligations_v0.schema.json").read_text())
assert_embedded_artifact_schemas_match(
    check_report_schema,
    "check_report_v0",
    compile_report_schema,
    "compile_report_v0",
)
assert_embedded_artifact_schemas_match(
    check_report_schema,
    "check_report_v0",
    verified_artifacts_schema,
    "verified_artifacts_v0",
)
assert_verified_bundle_schema_uses_embedded_artifacts(verified_artifacts_schema)
for report_schema, report_name in [
    (check_report_schema, "check_report_v0"),
    (compile_report_schema, "compile_report_v0"),
]:
    assert_embedded_ir_model_search_obligations_aligned(
        report_schema,
        report_name,
        ir_model_search_obligations_schema,
    )
for report_schema, report_name in [
    (check_report_schema, "check_report_v0"),
    (compile_report_schema, "compile_report_v0"),
    (verified_artifacts_schema, "verified_artifacts_v0"),
]:
    assert_embedded_package_contract_catalog_aligned(
        report_schema,
        report_name,
        package_contract_schema,
    )
    assert_embedded_artifact_schema_aligned(
        report_schema,
        report_name,
        construct_graph_schema,
        "construct_graph",
        ["nodes", "ports", "edges", "effect_dependencies"],
    )
    assert_embedded_artifact_schema_aligned(
        report_schema,
        report_name,
        lowered_ir_schema,
        "lowered_ir_report",
        ["node_lowerings", "edge_lowerings", "dependency_lowerings", "core_objects"],
    )
    assert_embedded_derived_fact_aligned(
        report_schema,
        report_name,
        construct_graph_schema,
        "construct_graph_v0",
    )
    assert_embedded_derived_fact_aligned(
        report_schema,
        report_name,
        lowered_ir_schema,
        "lowered_ir_report_v0",
    )
standalone_catalog = {
    key: value
    for key, value in platform_catalog_schema.items()
    if key not in ["$schema", "$id", "title", "$defs"]
}
if package_contract_schema.get("properties", {}).get("platform_construct_catalog") != standalone_catalog:
    fail("package_contract_v0 platform_construct_catalog schema drifted from standalone platform catalog schema")
assert_embedded_platform_catalog_aligned(
    package_check_schema,
    "package_check_v0",
    platform_catalog_schema,
)
for def_name in ["string_array", "platform_construct_family", "platform_construct_lowering"]:
    if package_contract_schema.get("$defs", {}).get(def_name) != platform_catalog_schema.get("$defs", {}).get(def_name):
        fail(f"package_contract_v0 {def_name} schema drifted from standalone platform catalog schema")
print("validated embedded artifact schema contracts stay aligned with standalone schemas")

for report_name in [
    "event-bridge-compile-model-search",
    "scheduled-escalation-compile-model-search",
    "provider-language-compile-model-search",
    "terminal-output-compile-model-search",
]:
    report = json.loads((tmp_dir / f"{report_name}.json").read_text())
    artifact = report.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        fail(f"{report_name}.json missing ir_model_search_obligations artifact")
    (tmp_dir / f"{report_name}.ir-model-search-obligations.json").write_text(
        json.dumps(artifact)
    )

pairs = [
    ("spec/report-schemas/check_report_v0.schema.json", tmp_dir / "check.json"),
    ("spec/report-schemas/compile_report_v0.schema.json", tmp_dir / "compile.json"),
    ("spec/report-schemas/compile_report_v0.schema.json", tmp_dir / "event-bridge-compile.json"),
    ("spec/report-schemas/compile_report_v0.schema.json", tmp_dir / "scheduled-escalation-compile.json"),
    ("spec/report-schemas/compile_report_v0.schema.json", tmp_dir / "event-bridge-compile-model-search.json"),
    ("spec/report-schemas/compile_report_v0.schema.json", tmp_dir / "scheduled-escalation-compile-model-search.json"),
    ("spec/report-schemas/compile_report_v0.schema.json", tmp_dir / "provider-language-compile-model-search.json"),
    ("spec/report-schemas/compile_report_v0.schema.json", tmp_dir / "terminal-output-compile-model-search.json"),
    ("spec/report-schemas/ir_model_search_obligations_v0.schema.json", tmp_dir / "event-bridge-compile-model-search.ir-model-search-obligations.json"),
    ("spec/report-schemas/ir_model_search_obligations_v0.schema.json", tmp_dir / "scheduled-escalation-compile-model-search.ir-model-search-obligations.json"),
    ("spec/report-schemas/ir_model_search_obligations_v0.schema.json", tmp_dir / "provider-language-compile-model-search.ir-model-search-obligations.json"),
    ("spec/report-schemas/ir_model_search_obligations_v0.schema.json", tmp_dir / "terminal-output-compile-model-search.ir-model-search-obligations.json"),
    ("spec/report-schemas/verified_artifacts_v0.schema.json", tmp_dir / "compile-verified-construct-graph.json"),
    ("spec/report-schemas/verified_artifacts_v0.schema.json", tmp_dir / "compile-verified-construct-graph.roundtrip.json"),
    ("spec/report-schemas/verified_artifacts_v0.schema.json", tmp_dir / "compile-verified-artifacts.json"),
    ("spec/report-schemas/verified_artifacts_v0.schema.json", tmp_dir / "compile-verified-lowered-ir.json"),
    ("spec/report-schemas/compile_report_v0.schema.json", tmp_dir / "compile-error.json"),
    ("spec/report-schemas/dev_report_v0.schema.json", tmp_dir / "dev.json"),
    ("spec/report-schemas/test_report_v0.schema.json", tmp_dir / "test.json"),
    ("spec/report-schemas/local_trace_v0.schema.json", tmp_dir / "trace.json"),
    ("spec/report-schemas/acceptance_fixture_v0.schema.json", Path("examples/provider-language-e2e.accept.json")),
    ("spec/report-schemas/acceptance_report_v0.schema.json", tmp_dir / "acceptance.json"),
    ("spec/report-schemas/package_manifest_v0.schema.json", Path("std/manifests/memory.json")),
    ("spec/report-schemas/package_check_v0.schema.json", tmp_dir / "package-check.json"),
    ("spec/report-schemas/platform_construct_catalog_v0.schema.json", tmp_dir / "platform-construct-catalog.json"),
    ("spec/report-schemas/package_lock_v0.schema.json", tmp_dir / "package-lock.json"),
    ("spec/report-schemas/package_lock_v0.schema.json", tmp_dir / "package-lock-stdout.json"),
    ("spec/report-schemas/check_report_v0.schema.json", tmp_dir / "package-memory-check.json"),
    ("spec/report-schemas/check_report_v0.schema.json", tmp_dir / "package-memory-check-model-search.json"),
]

for schema_path, report_path in pairs:
    schema = json.loads(Path(schema_path).read_text())
    report = json.loads(report_path.read_text())
    Draft202012Validator(schema).validate(report)
    print(f"validated {report_path.name} against {Path(schema_path).name}")

verified_artifacts_validator = Draft202012Validator(verified_artifacts_schema)
verified_artifacts = json.loads((tmp_dir / "compile-verified-artifacts.json").read_text())
for field in ["package_contract", "construct_graph", "lowered_ir_report"]:
    mutated = copy.deepcopy(verified_artifacts)
    mutated["entries"][0][field] = {}
    assert_schema_rejects(
        verified_artifacts_validator,
        mutated,
        f"verified artifact bundle with empty {field}",
    )
print("validated verified artifact bundle schema rejects empty embedded artifacts")

package_manifest_schema = json.loads(Path("spec/report-schemas/package_manifest_v0.schema.json").read_text())
package_manifest_validator = Draft202012Validator(package_manifest_schema)
package_manifest = json.loads(Path("std/manifests/memory.json").read_text())
assert_schema_rejects(
    package_manifest_validator,
    with_duplicate_array_member(
        package_manifest,
        ["libraries", "capabilities", "providers", "profiles", "bindings"],
        "package manifest",
    ),
    "package manifest with duplicate top-level identity member",
)
assert_schema_rejects(
    package_manifest_validator,
    with_duplicate_package_manifest_string_array(package_manifest, "package manifest"),
    "package manifest with duplicate string-array value",
)
package_lock_schema = json.loads(Path("spec/report-schemas/package_lock_v0.schema.json").read_text())
package_lock_validator = Draft202012Validator(package_lock_schema)
package_lock = json.loads((tmp_dir / "package-lock.json").read_text())
assert_schema_rejects(
    package_lock_validator,
    with_duplicate_array_member(package_lock, ["packages"], "package lock"),
    "package lock with duplicate package entry",
)
package_contract_validator = Draft202012Validator(package_contract_schema)
for label, package_contract in [
    ("package-check.package_contract", json.loads((tmp_dir / "package-check.json").read_text())["package_contract"]),
    ("check.package_contract", json.loads((tmp_dir / "check.json").read_text())[0]["package_contract"]),
    ("compile.package_contract", json.loads((tmp_dir / "compile.json").read_text())["package_contract"]),
    ("package-memory-check.package_contract", json.loads((tmp_dir / "package-memory-check.json").read_text())[0]["package_contract"]),
]:
    package_contract_validator.validate(package_contract)
    print(f"validated {label} against package_contract_v0.schema.json")
assert_schema_rejects(
    package_contract_validator,
    with_duplicate_array_member(
        json.loads((tmp_dir / "package-check.json").read_text())["package_contract"],
        ["manifests"],
        "package contract",
    ),
    "package contract with duplicate manifest summary",
)
bad_package_contract = copy.deepcopy(json.loads((tmp_dir / "package-check.json").read_text())["package_contract"])
del bad_package_contract["platform_construct_catalog"]["lowerings"]
assert_schema_rejects(
    package_contract_validator,
    bad_package_contract,
    "package contract with incomplete platform construct catalog",
)
bad_package_contract = copy.deepcopy(json.loads((tmp_dir / "package-check.json").read_text())["package_contract"])
bad_package_contract["platform_construct_catalog"]["unexpected"] = True
assert_schema_rejects(
    package_contract_validator,
    bad_package_contract,
    "package contract with unknown platform construct catalog property",
)
bad_package_contract = copy.deepcopy(json.loads((tmp_dir / "package-check.json").read_text())["package_contract"])
bad_package_contract["platform_construct_catalog"]["lowerings"][0]["target_capability"] = "runtime_magic"
assert_schema_rejects(
    package_contract_validator,
    bad_package_contract,
    "package contract with unsupported platform lowering target capability",
)
platform_catalog_validator = Draft202012Validator(platform_catalog_schema)
platform_catalog = json.loads((tmp_dir / "platform-construct-catalog.json").read_text())
assert_schema_rejects(
    platform_catalog_validator,
    with_duplicate_array_member(platform_catalog, ["families"], "platform construct catalog"),
    "platform construct catalog with duplicate family member",
)
assert_schema_rejects(
    platform_catalog_validator,
    with_duplicate_array_member(platform_catalog, ["lowerings"], "platform construct catalog"),
    "platform construct catalog with duplicate lowering member",
)
bad_platform_catalog = copy.deepcopy(platform_catalog)
bad_platform_catalog["interface_kinds"].append(bad_platform_catalog["interface_kinds"][0])
assert_schema_rejects(
    platform_catalog_validator,
    bad_platform_catalog,
    "platform construct catalog with duplicate interface kind",
)
print("validated package manifest/lock/contract/catalog schemas reject duplicate identity and string-set members")

package_check = json.loads((tmp_dir / "package-check.json").read_text())
catalog = package_check.get("platform_construct_catalog")
if catalog is None:
    raise SystemExit("package-check.json missing platform_construct_catalog")
standalone_catalog = json.loads((tmp_dir / "platform-construct-catalog.json").read_text())
if standalone_catalog != catalog:
    raise SystemExit("whip package catalog drifted from package-check platform_construct_catalog")
family_ids = [family.get("id") for family in catalog.get("families", [])]
if family_ids != [
    "declaration_block",
    "effect_operation",
    "effect_contract",
    "source_declaration",
    "assertion",
    "rule",
    "projection_read",
]:
    raise SystemExit(f"unexpected platform construct families: {family_ids!r}")
lowering_ids = [lowering.get("id") for lowering in catalog.get("lowerings", [])]
if lowering_ids != [
    "metadata",
    "metadata_only",
    "capability_call",
    "typed_effect_call",
    "resource_effect",
    "core_effect",
    "signal_emit",
    "signal_source",
    "clock_source",
    "schedule_emitter",
    "rule_template",
    "projection_view",
    "assertion_check",
]:
    raise SystemExit(f"unexpected platform construct lowerings: {lowering_ids!r}")
interface_kinds = catalog.get("interface_kinds", [])
if "Capability" not in interface_kinds or "EffectHandle" not in interface_kinds:
    raise SystemExit(f"platform construct catalog missing expected interface kinds: {interface_kinds!r}")
capability_call = next(
    (lowering for lowering in catalog.get("lowerings", []) if lowering.get("id") == "capability_call"),
    None,
)
if capability_call is None:
    raise SystemExit("platform construct catalog missing capability_call lowering")
if capability_call.get("required_interfaces") != ["Capability"]:
    raise SystemExit(f"capability_call required interfaces drifted: {capability_call!r}")
if capability_call.get("provided_interfaces") != ["EffectHandle"]:
    raise SystemExit(f"capability_call provided interfaces drifted: {capability_call!r}")
if capability_call.get("compatible_families") != ["effect_operation"]:
    raise SystemExit(f"capability_call compatible families drifted: {capability_call!r}")
if capability_call.get("package_authorable") is not True:
    raise SystemExit(f"capability_call package authorability drifted: {capability_call!r}")
if capability_call.get("lifecycle_profiles") != ["effect_graph", "typed_effect_graph"]:
    raise SystemExit(f"capability_call lifecycle profiles drifted: {capability_call!r}")
if capability_call.get("authority_profile") != "capability_scoped":
    raise SystemExit(f"capability_call authority profile drifted: {capability_call!r}")
for guarantee in [
    "deterministic",
    "contract_pinned",
    "no_runtime_inputs",
    "no_hidden_authority",
    "no_package_scheduler",
    "no_package_lifecycle",
    "no_direct_fact_write",
    "no_direct_rule_fire",
]:
    if guarantee not in capability_call.get("static_guarantees", []):
        raise SystemExit(f"capability_call static guarantees missing {guarantee}: {capability_call!r}")
signal_source_lowering = next(
    (lowering for lowering in catalog.get("lowerings", []) if lowering.get("id") == "signal_source"),
    None,
)
if signal_source_lowering is None:
    raise SystemExit("platform construct catalog missing signal_source lowering")
if signal_source_lowering.get("package_authorable") is not False:
    raise SystemExit(f"signal_source authorability drifted: {signal_source_lowering!r}")
if signal_source_lowering.get("lifecycle_profiles") != ["signal_source_template"]:
    raise SystemExit(f"signal_source lifecycle profiles drifted: {signal_source_lowering!r}")
sys.path.insert(0, str(Path("scripts").resolve()))
from artifact_admission import (
    expected_platform_version,
    validate_contract_registry_shape,
	validate_package_contract_spine,
	validate_package_contract_platform,
	validate_platform_construct_catalog_shape,
)
validate_platform_construct_catalog_shape(catalog, "package-check.platform_construct_catalog")
for duplicate_field, expected_fragment in [
    ("families", "duplicates id"),
    ("lowerings", "duplicates id"),
]:
    bad_catalog = copy.deepcopy(catalog)
    duplicate = copy.deepcopy(bad_catalog[duplicate_field][0])
    if duplicate_field == "families":
        duplicate["description"] = "duplicate id with different description"
    else:
        duplicate["provided_interfaces"] = []
    bad_catalog[duplicate_field].append(duplicate)
    try:
        validate_platform_construct_catalog_shape(
            bad_catalog,
            "package-check.platform_construct_catalog",
        )
    except SystemExit as exc:
        if expected_fragment not in str(exc):
            raise SystemExit(
                f"unexpected platform catalog admission error for {duplicate_field}: {exc}"
            )
    else:
        raise SystemExit(
            f"platform catalog admission accepted duplicate {duplicate_field} id"
        )
package_contract = package_check.get("package_contract")
if package_contract.get("platform_version") != expected_platform_version(Path.cwd()):
    raise SystemExit("package contract platform_version drifted from workspace package version")
validate_contract_registry_shape(
    package_contract.get("contract_registry"),
    "package_contract.contract_registry",
)
validate_package_contract_spine(package_contract, "package_contract")
validate_package_contract_platform(
    Path.cwd(),
    catalog,
    package_contract,
    "package_contract",
)
bad_package_contract = copy.deepcopy(package_contract)
package_constructs = bad_package_contract["contract_registry"]["constructs"]
package_constructs[0]["lowering_target"] = "core_effect"
try:
    validate_package_contract_platform(
        Path.cwd(),
        catalog,
        bad_package_contract,
        "package_contract",
    )
except SystemExit as exc:
    if "platform-internal" not in str(exc):
        raise SystemExit(
            f"unexpected package contract platform admission error for internal lowering: {exc}"
        )
else:
    raise SystemExit("package contract platform admission accepted package use of internal lowering")
for field_path, expected_fragment in [
    (("contract_registry", "libraries"), "contract_registry.libraries must be an array"),
    (("manifests",), "package_contract.manifests must be an array"),
    (("package_lock_digest",), "package_contract.package_lock_digest must be a 64-character lowercase hex digest"),
]:
    bad_package_contract = copy.deepcopy(package_contract)
    target = bad_package_contract
    for field in field_path[:-1]:
        target = target[field]
    del target[field_path[-1]]
    try:
        validate_package_contract_spine(bad_package_contract, "package_contract")
    except SystemExit as exc:
        if expected_fragment not in str(exc):
            raise SystemExit(
                f"unexpected package contract spine admission error for {field_path}: {exc}"
            )
    else:
        raise SystemExit(f"package contract spine accepted missing {field_path}")

construct_graph_schema = json.loads(Path("spec/report-schemas/construct_graph_v0.schema.json").read_text())
construct_graph_validator = Draft202012Validator(construct_graph_schema)
lowered_ir_schema = json.loads(Path("spec/report-schemas/lowered_ir_report_v0.schema.json").read_text())
lowered_ir_validator = Draft202012Validator(lowered_ir_schema)
for report_path in [tmp_dir / "check.json", tmp_dir / "package-memory-check.json"]:
    report = json.loads(report_path.read_text())
    if not isinstance(report, list):
        raise SystemExit(f"{report_path.name} was not a check report array")
    for index, entry in enumerate(report):
        graph = entry.get("construct_graph")
        if graph is None:
            raise SystemExit(f"{report_path.name}[{index}] missing construct_graph")
        construct_graph_validator.validate(graph)
        print(f"validated {report_path.name}[{index}].construct_graph against construct_graph_v0.schema.json")
        lowered = entry.get("lowered_ir_report")
        if lowered is None:
            raise SystemExit(f"{report_path.name}[{index}] missing lowered_ir_report")
        lowered_ir_validator.validate(lowered)
        print(f"validated {report_path.name}[{index}].lowered_ir_report against lowered_ir_report_v0.schema.json")

compile_report = json.loads((tmp_dir / "compile.json").read_text())
compile_graph = compile_report.get("construct_graph")
if compile_graph is None:
    raise SystemExit("compile.json missing construct_graph")
construct_graph_validator.validate(compile_graph)
print("validated compile.json.construct_graph against construct_graph_v0.schema.json")

compile_lowered = compile_report.get("lowered_ir_report")
if compile_lowered is None:
    raise SystemExit("compile.json missing lowered_ir_report")
lowered_ir_validator.validate(compile_lowered)
print("validated compile.json.lowered_ir_report against lowered_ir_report_v0.schema.json")
for report_name, expected_entrypoints in [
    ("event-bridge-compile.json", {"assertion_check", "rule_template", "fact_record"}),
    ("scheduled-escalation-compile.json", {"schedule_template", "rule_template", "fact_record"}),
]:
    report = json.loads((tmp_dir / report_name).read_text())
    graph = report.get("construct_graph")
    if graph is None:
        raise SystemExit(f"{report_name} missing construct_graph")
    construct_graph_validator.validate(graph)
    print(f"validated {report_name}.construct_graph against construct_graph_v0.schema.json")
    lowered = report.get("lowered_ir_report")
    if lowered is None:
        raise SystemExit(f"{report_name} missing lowered_ir_report")
    lowered_ir_validator.validate(lowered)
    print(f"validated {report_name}.lowered_ir_report against lowered_ir_report_v0.schema.json")
    entrypoints = {
        obj.get("runtime_entrypoint")
        for obj in lowered.get("core_objects", [])
        if isinstance(obj, dict)
    }
    missing = sorted(expected_entrypoints - entrypoints)
    if missing:
        raise SystemExit(f"{report_name} missing lowered runtime entrypoint(s): {missing!r}")
package_memory_report = json.loads((tmp_dir / "package-memory-check.json").read_text())
write_bad_construct_graph_schema_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-schema.json",
)
write_bad_construct_graph_scalar_metadata_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-scalar-metadata.json",
)
write_bad_construct_graph_duplicate_scalar_resolution_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-duplicate-scalar-resolution.json",
)
write_bad_construct_graph_many_missing_order_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-many-missing-order.json",
)
write_bad_construct_graph_named_many_missing_key_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-named-many-missing-key.json",
)
write_bad_construct_graph_unknown_edge_field_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-unknown-edge-field.json",
)
write_bad_construct_graph_edge_evidence_type_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-edge-evidence-type.json",
)
write_bad_construct_graph_source_span_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-source-span.json",
)
write_bad_construct_graph_derived_fact_span_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-derived-fact-span.json",
)
write_bad_construct_graph_derived_fact_input_refs_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-derived-fact-input-refs.json",
)
write_bad_construct_graph_derived_fact_metadata_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-derived-fact-metadata.json",
)
write_bad_construct_graph_duplicate_derived_fact_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-derived-fact-duplicate.json",
)
write_bad_construct_graph_platform_version_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-platform-version-type.json",
)
write_bad_construct_graph_node_metadata_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-node-metadata-type.json",
)
write_bad_construct_graph_effect_dependency_rule_name_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-dependency-rule-name-type.json",
)
write_bad_construct_graph_diagnostic_span_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-diagnostic-span.json",
)
write_bad_construct_graph_diagnostic_metadata_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-diagnostic-metadata.json",
)
write_bad_construct_graph_diagnostics_type_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-diagnostics-type.json",
)
write_bad_construct_graph_unknown_output_vocabulary_report(
    compile_report,
    tmp_dir / "compile-bad-construct-unknown-output-vocabulary.json",
)
write_bad_construct_graph_lifecycle_profile_report(
    compile_report,
    tmp_dir / "compile-bad-construct-lifecycle-profile.json",
)
write_bad_construct_graph_missing_lowering_interface_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-missing-lowering-interface.json",
)
write_bad_lowered_output_vocabulary_report(
    compile_report,
    tmp_dir / "compile-bad-lowered-output-vocabulary.json",
)
write_bad_construct_graph_declared_interface_collection_report(
    package_memory_report,
    "declared_required_interfaces",
    tmp_dir / "package-memory-bad-construct-required-interfaces-type.json",
)
write_bad_construct_graph_declared_interface_collection_report(
    package_memory_report,
    "declared_provided_interfaces",
    tmp_dir / "package-memory-bad-construct-provided-interfaces-type.json",
)
write_bad_construct_graph_interface_phase_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-interface-phase.json",
)
write_bad_construct_graph_interface_cardinality_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-interface-cardinality.json",
)
write_bad_construct_graph_interface_type_report(
    package_memory_report,
    tmp_dir / "package-memory-bad-construct-interface-type.json",
)
compile_bad_lowered_schema = copy.deepcopy(compile_report)
compile_bad_lowered_schema["lowered_ir_report"]["schema"] = (
    "whipplescript.not_lowered_ir_report.v0"
)
(tmp_dir / "compile-bad-lowered-schema.json").write_text(
    json.dumps(compile_bad_lowered_schema)
)
compile_bad_lowered_lowerer_version = copy.deepcopy(compile_report)
compile_bad_lowered_lowerer_version["lowered_ir_report"]["lowerer_version"] = 1
(tmp_dir / "compile-bad-lowered-lowerer-version-type.json").write_text(
    json.dumps(compile_bad_lowered_lowerer_version)
)
compile_bad_lowered_preserved_predicate = copy.deepcopy(compile_report)
dependencies = compile_bad_lowered_preserved_predicate["lowered_ir_report"][
    "dependency_lowerings"
]
if not dependencies:
    raise SystemExit("compile lowered IR report did not contain dependency lowerings")
dependencies[0]["preserved_predicate"] = 1
(tmp_dir / "compile-bad-lowered-preserved-predicate-type.json").write_text(
    json.dumps(compile_bad_lowered_preserved_predicate)
)
event_bridge_model_search_report = json.loads(
    (tmp_dir / "event-bridge-compile-model-search.json").read_text()
)
provider_language_model_search_report = json.loads(
    (tmp_dir / "provider-language-compile-model-search.json").read_text()
)
terminal_output_model_search_report = json.loads(
    (tmp_dir / "terminal-output-compile-model-search.json").read_text()
)
package_memory_model_search_report = json.loads(
    (tmp_dir / "package-memory-check-model-search.json").read_text()
)
write_model_search_stale_construct_evidence_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-stale-construct-evidence.json",
)
write_model_search_bad_report_schema(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-bad-report-schema.json",
)
write_model_search_bad_ir_predicate_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-bad-ir-predicate.json",
)
write_model_search_stale_ir_obligations_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-stale-ir-obligations.json",
)
write_model_search_missing_ir_obligation_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-missing-ir-obligation.json",
)
write_model_search_wrong_ir_predicate_counts_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-wrong-ir-predicate-counts.json",
)
write_model_search_wrong_ir_endpoint_counts_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-wrong-ir-endpoint-counts.json",
)
write_model_search_wrong_ir_outcome_counts_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-wrong-ir-outcome-counts.json",
)
write_model_search_wrong_ir_sequence_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-wrong-ir-sequence.json",
)
write_model_search_wrong_ir_description_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-wrong-ir-description.json",
)
write_model_search_wrong_dependency_source_span_report(
    provider_language_model_search_report,
    tmp_dir / "provider-language-model-search-wrong-dependency-source-span.json",
)
write_model_search_wrong_handoff_source_span_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-wrong-handoff-source-span.json",
)
write_model_search_wrong_dependency_source_span_with_graph_report(
    package_memory_model_search_report,
    tmp_dir / "package-memory-model-search-wrong-dependency-source-span-with-graph.json",
)
write_model_search_wrong_assertion_source_span_report(
    provider_language_model_search_report,
    tmp_dir / "provider-language-model-search-wrong-assertion-source-span.json",
)
write_model_search_wrong_revision_source_span_report(
    provider_language_model_search_report,
    tmp_dir / "provider-language-model-search-wrong-revision-source-span.json",
)
write_model_search_wrong_guard_source_span_report(
    provider_language_model_search_report,
    tmp_dir / "provider-language-model-search-wrong-guard-source-span.json",
)
write_model_search_wrong_guard_source_span_with_anchor_report(
    provider_language_model_search_report,
    tmp_dir / "provider-language-model-search-wrong-guard-source-span-with-anchor.json",
)
write_model_search_wrong_terminal_source_span_report(
    terminal_output_model_search_report,
    tmp_dir / "terminal-output-model-search-wrong-terminal-source-span.json",
)
write_model_search_unsupported_ir_obligation_report(
    event_bridge_model_search_report,
    tmp_dir / "event-bridge-model-search-unsupported-ir-obligation.json",
)
assert_schema_rejects(
    construct_graph_validator,
    with_duplicate_array_member(
        compile_graph,
        ["nodes", "ports", "edges", "effect_dependencies", "derived_facts"],
        "compile construct graph",
    ),
    "standalone construct graph with duplicate top-level inventory member",
)
assert_schema_rejects(
    construct_graph_validator,
    with_duplicate_derived_fact_input_ref(compile_graph, "compile construct graph"),
    "standalone construct graph with duplicate derived fact input_refs",
)
assert_schema_rejects(
    construct_graph_validator,
    with_duplicate_construct_graph_string_ref(compile_graph, "compile construct graph"),
    "standalone construct graph with duplicate string-array refs",
)
assert_schema_rejects(
    construct_graph_validator,
    with_duplicate_construct_graph_interface(compile_graph, "compile construct graph"),
    "standalone construct graph with duplicate declared interfaces",
)
assert_schema_rejects(
    construct_graph_validator,
    with_invalid_construct_graph_output_vocabulary(compile_graph, "compile construct graph"),
    "standalone construct graph with stale output vocabulary",
)
assert_schema_rejects(
    lowered_ir_validator,
    with_duplicate_array_member(
        compile_lowered,
        [
            "node_lowerings",
            "edge_lowerings",
            "dependency_lowerings",
            "core_objects",
            "derived_facts",
        ],
        "compile lowered IR report",
    ),
    "standalone lowered IR report with duplicate top-level inventory member",
)
assert_schema_rejects(
    lowered_ir_validator,
    with_duplicate_derived_fact_input_ref(compile_lowered, "compile lowered IR report"),
    "standalone lowered IR report with duplicate derived fact input_refs",
)
assert_schema_rejects(
    lowered_ir_validator,
    with_duplicate_lowered_ir_witness_ref(compile_lowered, "compile lowered IR report"),
    "standalone lowered IR report with duplicate lowering witness refs",
)
assert_schema_rejects(
    lowered_ir_validator,
    with_duplicate_lowered_ir_core_object_metadata_ref(
        compile_lowered,
        "compile lowered IR report",
    ),
    "standalone lowered IR report with duplicate core object metadata refs",
)
print("validated artifact schemas reject duplicate construct graph refs/interfaces, stale output vocabulary, lowered IR witness/core-object metadata refs, and derived fact input_refs")

compile_report_schema = json.loads(Path("spec/report-schemas/compile_report_v0.schema.json").read_text())
compile_report_validator = Draft202012Validator(compile_report_schema)
compile_with_model_search = copy.deepcopy(compile_report)
compile_with_model_search["model_search"] = {
    "status": "ok",
    "searches": 1,
    "solutions": 1,
    "no_solutions": 0,
    "ir_searches": 0,
    "artifact_searches": 1,
    "obligations": [
        {
            "category": "artifact.construct_graph",
            "index": 1,
            "description": "construct graph artifact",
            "upstream": "construct-graph-artifact",
            "predicate": "graphAccepted",
            "downstream": "construct-graph-artifact",
            "expected": "solution",
            "actual": "solution",
            "status": "ok",
            "source_span": {"start": 0, "end": 0},
        }
    ],
}
compile_report_validator.validate(compile_with_model_search)
bad_compile_model_search = copy.deepcopy(compile_report)
bad_compile_model_search["model_search"] = {
    "status": "ok",
    "searches": -1,
    "solutions": 0,
    "no_solutions": 0,
    "ir_searches": 0,
    "artifact_searches": 0,
    "obligations": [],
}
assert_schema_rejects(
    compile_report_validator,
    bad_compile_model_search,
    "compile report with invalid model_search counters",
)
bad_compile_model_search = copy.deepcopy(compile_with_model_search)
bad_compile_model_search["model_search"]["obligations"][0]["upstream"] = ""
assert_schema_rejects(
    compile_report_validator,
    bad_compile_model_search,
    "compile report with empty model_search formal endpoint",
)
print("validated compile report schema accepts checked model_search summaries")
ir_model_search_obligations_validator = Draft202012Validator(ir_model_search_obligations_schema)
ir_model_search_obligations = json.loads(
    (tmp_dir / "event-bridge-compile-model-search.ir-model-search-obligations.json").read_text()
)
bad_ir_model_search_obligations = copy.deepcopy(ir_model_search_obligations)
bad_ir_model_search_obligations["generator"] = ""
assert_schema_rejects(
    ir_model_search_obligations_validator,
    bad_ir_model_search_obligations,
    "IR model-search obligations artifact with empty generator",
)
bad_ir_model_search_obligations = copy.deepcopy(ir_model_search_obligations)
bad_ir_model_search_obligations["obligations"][0]["upstream"] = ""
assert_schema_rejects(
    ir_model_search_obligations_validator,
    bad_ir_model_search_obligations,
    "IR model-search obligations artifact with empty endpoint",
)
print("validated IR model-search obligations schema rejects malformed artifacts")
bad_compile = copy.deepcopy(compile_report)
del bad_compile["construct_graph"]["derived_facts"]
assert_schema_rejects(
    compile_report_validator,
    bad_compile,
    "compile report with incomplete embedded construct graph",
)
bad_compile = copy.deepcopy(compile_report)
del bad_compile["lowered_ir_report"]["core_objects"]
assert_schema_rejects(
    compile_report_validator,
    bad_compile,
    "compile report with incomplete embedded lowered IR report",
)
bad_compile = copy.deepcopy(compile_report)
bad_compile["construct_graph"] = with_duplicate_derived_fact_input_ref(
    bad_compile["construct_graph"],
    "embedded compile construct graph",
)
assert_schema_rejects(
    compile_report_validator,
    bad_compile,
    "compile report with duplicate embedded construct graph derived fact input_refs",
)
bad_compile = copy.deepcopy(compile_report)
bad_compile["construct_graph"] = with_duplicate_array_member(
    bad_compile["construct_graph"],
    ["nodes", "ports", "edges", "effect_dependencies", "derived_facts"],
    "embedded compile construct graph",
)
assert_schema_rejects(
    compile_report_validator,
    bad_compile,
    "compile report with duplicate embedded construct graph inventory member",
)
bad_compile = copy.deepcopy(compile_report)
bad_compile["lowered_ir_report"] = with_duplicate_derived_fact_input_ref(
    bad_compile["lowered_ir_report"],
    "embedded compile lowered IR report",
)
assert_schema_rejects(
    compile_report_validator,
    bad_compile,
    "compile report with duplicate embedded lowered IR derived fact input_refs",
)
bad_compile = copy.deepcopy(compile_report)
bad_compile["lowered_ir_report"] = with_duplicate_array_member(
    bad_compile["lowered_ir_report"],
    [
        "node_lowerings",
        "edge_lowerings",
        "dependency_lowerings",
        "core_objects",
        "derived_facts",
    ],
    "embedded compile lowered IR report",
)
assert_schema_rejects(
    compile_report_validator,
    bad_compile,
    "compile report with duplicate embedded lowered IR inventory member",
)
print("validated compile report schema rejects incomplete or duplicate embedded artifacts")

compile_error = json.loads((tmp_dir / "compile-error.json").read_text())
if compile_error.get("status") != "error":
    raise SystemExit("compile-error.json was not an error report")
if compile_error.get("error", {}).get("kind") != "package_lock":
    raise SystemExit("compile-error.json did not report package_lock")

package_check = json.loads((tmp_dir / "package-memory-check.json").read_text())
package_graph = package_check[0]["construct_graph"]
package_lowered = package_check[0]["lowered_ir_report"]
check_report_schema = json.loads(Path("spec/report-schemas/check_report_v0.schema.json").read_text())
check_report_validator = Draft202012Validator(check_report_schema)
bad_check = copy.deepcopy(package_check)
del bad_check[0]["construct_graph"]["derived_facts"]
assert_schema_rejects(
    check_report_validator,
    bad_check,
    "check report with incomplete embedded construct graph",
)
bad_check = copy.deepcopy(package_check)
del bad_check[0]["lowered_ir_report"]["derived_facts"]
assert_schema_rejects(
    check_report_validator,
    bad_check,
    "check report with incomplete embedded lowered IR report",
)
bad_check = copy.deepcopy(package_check)
bad_check[0]["construct_graph"] = with_duplicate_derived_fact_input_ref(
    bad_check[0]["construct_graph"],
    "embedded check construct graph",
)
assert_schema_rejects(
    check_report_validator,
    bad_check,
    "check report with duplicate embedded construct graph derived fact input_refs",
)
bad_check = copy.deepcopy(package_check)
bad_check[0]["construct_graph"] = with_duplicate_array_member(
    bad_check[0]["construct_graph"],
    ["nodes", "ports", "edges", "effect_dependencies", "derived_facts"],
    "embedded check construct graph",
)
assert_schema_rejects(
    check_report_validator,
    bad_check,
    "check report with duplicate embedded construct graph inventory member",
)
bad_check = copy.deepcopy(package_check)
bad_check[0]["lowered_ir_report"] = with_duplicate_derived_fact_input_ref(
    bad_check[0]["lowered_ir_report"],
    "embedded check lowered IR report",
)
assert_schema_rejects(
    check_report_validator,
    bad_check,
    "check report with duplicate embedded lowered IR derived fact input_refs",
)
bad_check = copy.deepcopy(package_check)
bad_check[0]["lowered_ir_report"] = with_duplicate_array_member(
    bad_check[0]["lowered_ir_report"],
    [
        "node_lowerings",
        "edge_lowerings",
        "dependency_lowerings",
        "core_objects",
        "derived_facts",
    ],
    "embedded check lowered IR report",
)
assert_schema_rejects(
    check_report_validator,
    bad_check,
    "check report with duplicate embedded lowered IR inventory member",
)
print("validated check report schema rejects incomplete or duplicate embedded artifacts")
if not package_graph["nodes"]:
    raise SystemExit("package-memory construct graph did not contain package-backed nodes")
if not package_graph["edges"]:
    raise SystemExit("package-memory construct graph did not contain package-backed edges")
if not package_lowered["node_lowerings"]:
    raise SystemExit("package-memory lowered IR report did not contain node lowerings")
if not package_lowered["edge_lowerings"]:
    raise SystemExit("package-memory lowered IR report did not contain edge lowerings")
if not any(
    core_object.get("object_kind") == "effect"
    and core_object.get("runtime_entrypoint") == "effect_graph_template"
    for core_object in package_lowered.get("core_objects", [])
):
    raise SystemExit("package-memory lowered IR report did not contain effect graph templates")
package_fact_predicates = {
    fact.get("predicate")
    for fact in package_graph.get("derived_facts", [])
}
if not any(
    isinstance(predicate, str) and predicate.startswith("validator.graph.accepted:")
    for predicate in package_fact_predicates
):
    raise SystemExit("package-memory construct graph did not contain validator acceptance facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("validator.graph.adequacy.source_lock_deterministic:")
    for predicate in package_fact_predicates
):
    raise SystemExit("package-memory construct graph did not contain source/lock adequacy facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("validator.graph.adequacy.lifecycle_boundary_declared:")
    for predicate in package_fact_predicates
):
    raise SystemExit("package-memory construct graph did not contain lifecycle boundary adequacy facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("validator.edge.type_compatible:")
    for predicate in package_fact_predicates
):
    raise SystemExit("package-memory construct graph did not contain validator edge compatibility facts")

package_lowered_fact_predicates = {
    fact.get("predicate")
    for fact in package_lowered.get("derived_facts", [])
}
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.graph.coverage:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain graph coverage facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.graph.deterministic:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain deterministic lowering facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.graph.report_complete:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain report completeness facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.node.lifecycle_inputs:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain node lifecycle input facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain node lifecycle runtime-entrypoint facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.node.preservation.terminal_binding:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain node terminal-binding preservation facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.edge.preservation.core_relation:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain edge core-relation preservation facts")
if package_lowered.get("dependency_lowerings") and not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.dependency.preservation.predicate:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain dependency predicate preservation facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.node.output_compat:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain node output compatibility facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.node.output_compat.allowed_runtime_entrypoints:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain node output allowed-runtime-entrypoint facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.core_object.entrypoint:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain core object entrypoint facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.graph.runtime_boundary:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain runtime boundary facts")
if not any(
    isinstance(predicate, str) and predicate.startswith("lowered_ir.validator.graph.no_runtime_inputs:")
    for predicate in package_lowered_fact_predicates
):
    raise SystemExit("package-memory lowered IR report did not contain no-runtime-input facts")

stream_schema = json.loads(Path("spec/report-schemas/dev_stream_v0.schema.json").read_text())
dev_schema = json.loads(Path("spec/report-schemas/dev_report_v0.schema.json").read_text())
stream_events = [
    json.loads(line)
    for line in (tmp_dir / "dev-stream.ndjson").read_text().splitlines()
    if line.strip()
]
if not stream_events:
    raise SystemExit("dev-stream.ndjson did not contain events")
for index, event in enumerate(stream_events):
    Draft202012Validator(stream_schema).validate(event)
    if event.get("sequence") != index:
        raise SystemExit(f"stream sequence mismatch at line {index}")
final = stream_events[-1]
if final.get("event") != "dev.report":
    raise SystemExit("final stream event was not dev.report")
Draft202012Validator(dev_schema).validate(final["data"])
print("validated dev-stream.ndjson against dev_stream_v0.schema.json")
PY

validate_artifact_reports \
  "$TMP_DIR/check.json" \
  "$TMP_DIR/package-memory-check.json" \
  "$TMP_DIR/compile.json" \
  "$TMP_DIR/event-bridge-compile.json" \
  "$TMP_DIR/scheduled-escalation-compile.json" \
  "$TMP_DIR/event-bridge-compile-model-search.json" \
  "$TMP_DIR/scheduled-escalation-compile-model-search.json" \
  "$TMP_DIR/provider-language-compile-model-search.json" \
  "$TMP_DIR/terminal-output-compile-model-search.json" \
  "$TMP_DIR/compile-verified-construct-graph.json" \
  "$TMP_DIR/compile-verified-artifacts.json" \
  "$TMP_DIR/compile-verified-lowered-ir.json"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-schema.json" \
  2> "$TMP_DIR/package-memory-bad-construct-schema.err"; then
  echo "expected artifact report validator to reject invalid construct graph schema" >&2
  exit 1
fi
grep -Eq 'was expected|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-schema.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-schema.json" \
  > "$TMP_DIR/package-memory-bad-construct-schema.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-schema.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph schema" >&2
  exit 1
fi
grep -Eq 'was expected|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-schema.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-scalar-metadata.json" \
  2> "$TMP_DIR/package-memory-bad-construct-scalar-metadata.err"; then
  echo "expected artifact report validator to reject scalar cardinality aggregate metadata" >&2
  exit 1
fi
grep -q 'carries aggregate metadata' "$TMP_DIR/package-memory-bad-construct-scalar-metadata.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-scalar-metadata.json" \
  > "$TMP_DIR/package-memory-bad-construct-scalar-metadata.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-scalar-metadata.bridge.err"; then
  echo "expected construct graph bridge to reject scalar cardinality aggregate metadata" >&2
  exit 1
fi
grep -q 'carries aggregate metadata' "$TMP_DIR/package-memory-bad-construct-scalar-metadata.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.json" \
  2> "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.err"; then
  echo "expected artifact report validator to reject duplicate scalar cardinality resolution" >&2
  exit 1
fi
grep -q 'expects exactly one provider but resolved 2' \
  "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.json" \
  > "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.bridge.err"; then
  echo "expected construct graph bridge to reject duplicate scalar cardinality resolution" >&2
  exit 1
fi
grep -q 'expects exactly one provider but resolved 2' \
  "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-many-missing-order.json" \
  2> "$TMP_DIR/package-memory-bad-construct-many-missing-order.err"; then
  echo "expected artifact report validator to reject many cardinality without order" >&2
  exit 1
fi
grep -q 'missing order_index' "$TMP_DIR/package-memory-bad-construct-many-missing-order.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-many-missing-order.json" \
  > "$TMP_DIR/package-memory-bad-construct-many-missing-order.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-many-missing-order.bridge.err"; then
  echo "expected construct graph bridge to reject many cardinality without order" >&2
  exit 1
fi
grep -q 'missing order_index' "$TMP_DIR/package-memory-bad-construct-many-missing-order.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.json" \
  2> "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.err"; then
  echo "expected artifact report validator to reject named-many cardinality without resource key" >&2
  exit 1
fi
grep -q 'missing resource_key' "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.json" \
  > "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.bridge.err"; then
  echo "expected construct graph bridge to reject named-many cardinality without resource key" >&2
  exit 1
fi
grep -q 'missing resource_key' \
  "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.json" \
  2> "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.err"; then
  echo "expected artifact report validator to reject unknown construct graph edge field" >&2
  exit 1
fi
grep -q 'Additional properties are not allowed' \
  "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.json" \
  > "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.bridge.err"; then
  echo "expected construct graph bridge to reject unknown construct graph edge field" >&2
  exit 1
fi
grep -q 'Additional properties are not allowed' \
  "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.json" \
  2> "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.err"; then
  echo "expected artifact report validator to reject invalid construct graph edge evidence collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph edge evidence collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-source-span.json" \
  2> "$TMP_DIR/package-memory-bad-construct-source-span.err"; then
  echo "expected artifact report validator to reject invalid construct graph source span" >&2
  exit 1
fi
grep -q 'less than the minimum' \
  "$TMP_DIR/package-memory-bad-construct-source-span.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-source-span.json" \
  > "$TMP_DIR/package-memory-bad-construct-source-span.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-source-span.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph source span" >&2
  exit 1
fi
grep -q 'less than the minimum' \
  "$TMP_DIR/package-memory-bad-construct-source-span.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-span.json" \
  2> "$TMP_DIR/package-memory-bad-construct-derived-fact-span.err"; then
  echo "expected artifact report validator to reject invalid construct graph derived fact span" >&2
  exit 1
fi
grep -Eq 'less than the minimum|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-span.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-span.json" \
  > "$TMP_DIR/package-memory-bad-construct-derived-fact-span.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-derived-fact-span.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph derived fact span" >&2
  exit 1
fi
grep -Eq 'less than the minimum|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-span.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.json" \
  2> "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.err"; then
  echo "expected artifact report validator to reject duplicate construct graph derived fact input refs" >&2
  exit 1
fi
grep -Eq 'non-unique|duplicate input_refs|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.json" \
  > "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.bridge.err"; then
  echo "expected construct graph bridge to reject duplicate construct graph derived fact input refs" >&2
  exit 1
fi
grep -Eq 'non-unique|duplicate input_refs|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.json" \
  2> "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.err"; then
  echo "expected artifact report validator to reject invalid construct graph derived fact metadata" >&2
  exit 1
fi
grep -Eq 'should be non-empty|is too short|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.json" \
  > "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph derived fact metadata" >&2
  exit 1
fi
grep -Eq 'should be non-empty|is too short|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.json" \
  2> "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.err"; then
  echo "expected artifact report validator to reject duplicate construct graph derived facts" >&2
  exit 1
fi
grep -Eq 'non-unique|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.json" \
  > "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.bridge.err"; then
  echo "expected construct graph bridge to reject duplicate construct graph derived facts" >&2
  exit 1
fi
grep -Eq 'non-unique|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-platform-version-type.json" \
  2> "$TMP_DIR/package-memory-bad-construct-platform-version-type.err"; then
  echo "expected artifact report validator to reject invalid construct graph platform_version" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/package-memory-bad-construct-platform-version-type.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-platform-version-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-platform-version-type.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-platform-version-type.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph platform_version" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/package-memory-bad-construct-platform-version-type.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-node-metadata-type.json" \
  2> "$TMP_DIR/package-memory-bad-construct-node-metadata-type.err"; then
  echo "expected artifact report validator to reject invalid construct graph node metadata" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/package-memory-bad-construct-node-metadata-type.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-node-metadata-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-node-metadata-type.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-node-metadata-type.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph node metadata" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/package-memory-bad-construct-node-metadata-type.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.json" \
  2> "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.err"; then
  echo "expected artifact report validator to reject invalid construct graph dependency rule_name" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph dependency rule_name" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-span.json" \
  2> "$TMP_DIR/package-memory-bad-construct-diagnostic-span.err"; then
  echo "expected artifact report validator to reject invalid construct graph diagnostic span" >&2
  exit 1
fi
grep -Eq 'less than the minimum|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-span.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-span.json" \
  > "$TMP_DIR/package-memory-bad-construct-diagnostic-span.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-diagnostic-span.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph diagnostic span" >&2
  exit 1
fi
grep -Eq 'less than the minimum|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-span.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.json" \
  2> "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.err"; then
  echo "expected artifact report validator to reject invalid construct graph diagnostic metadata" >&2
  exit 1
fi
grep -Eq 'not one of|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.json" \
  > "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph diagnostic metadata" >&2
  exit 1
fi
grep -Eq 'not one of|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-diagnostics-type.json" \
  2> "$TMP_DIR/package-memory-bad-construct-diagnostics-type.err"; then
  echo "expected artifact report validator to reject invalid construct graph diagnostics collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-diagnostics-type.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-diagnostics-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-diagnostics-type.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-diagnostics-type.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph diagnostics collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-diagnostics-type.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.json" \
  2> "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.err"; then
  echo "expected artifact report validator to reject invalid construct graph required interface collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph required interface collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.json" \
  2> "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.err"; then
  echo "expected artifact report validator to reject invalid construct graph provided interface collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph provided interface collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.json" \
  2> "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.err"; then
  echo "expected artifact report validator to reject missing catalog-required lowering interface" >&2
  exit 1
fi
grep -q "declares no required 'Capability' interface" \
  "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.json" \
  > "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.bridge.err"; then
  echo "expected construct graph bridge to reject missing catalog-required lowering interface" >&2
  exit 1
fi
grep -q "declares no required 'Capability' interface" \
  "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.bridge.err"
if lowered_ir_to_maude \
  "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.json" \
  > "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.lowered.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.lowered.err"; then
  echo "expected lowered IR bridge to reject missing catalog-required lowering interface" >&2
  exit 1
fi
grep -q "declares no required 'Capability' interface" \
  "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.lowered.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-interface-phase.json" \
  2> "$TMP_DIR/package-memory-bad-construct-interface-phase.err"; then
  echo "expected artifact report validator to reject declared interface phase mismatch" >&2
  exit 1
fi
grep -q 'no required port satisfies it' \
  "$TMP_DIR/package-memory-bad-construct-interface-phase.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-interface-phase.json" \
  > "$TMP_DIR/package-memory-bad-construct-interface-phase.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-interface-phase.bridge.err"; then
  echo "expected construct graph bridge to reject declared interface phase mismatch" >&2
  exit 1
fi
grep -q 'no required port satisfies it' \
  "$TMP_DIR/package-memory-bad-construct-interface-phase.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-interface-cardinality.json" \
  2> "$TMP_DIR/package-memory-bad-construct-interface-cardinality.err"; then
  echo "expected artifact report validator to reject declared interface cardinality mismatch" >&2
  exit 1
fi
grep -q 'no provided port satisfies it' \
  "$TMP_DIR/package-memory-bad-construct-interface-cardinality.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-interface-cardinality.json" \
  > "$TMP_DIR/package-memory-bad-construct-interface-cardinality.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-interface-cardinality.bridge.err"; then
  echo "expected construct graph bridge to reject declared interface cardinality mismatch" >&2
  exit 1
fi
grep -q 'no provided port satisfies it' \
  "$TMP_DIR/package-memory-bad-construct-interface-cardinality.bridge.err"
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-interface-type.json" \
  2> "$TMP_DIR/package-memory-bad-construct-interface-type.err"; then
  echo "expected artifact report validator to reject invalid construct graph interface type" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/package-memory-bad-construct-interface-type.err"
if construct_graph_to_maude \
  "$TMP_DIR/package-memory-bad-construct-interface-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-interface-type.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-interface-type.bridge.err"; then
  echo "expected construct graph bridge to reject invalid construct graph interface type" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/package-memory-bad-construct-interface-type.bridge.err"
cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/check.json" \
  "$TMP_DIR/package-memory-check.json" \
  "$TMP_DIR/compile.json" \
  "$TMP_DIR/event-bridge-compile.json" \
  "$TMP_DIR/scheduled-escalation-compile.json" \
  "$TMP_DIR/event-bridge-compile-model-search.json" \
  "$TMP_DIR/scheduled-escalation-compile-model-search.json" \
  "$TMP_DIR/provider-language-compile-model-search.json" \
  "$TMP_DIR/terminal-output-compile-model-search.json"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.json" \
  > "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject missing catalog-required lowering interface" >&2
  exit 1
fi
grep -q 'construct_graph.interface.lowering_required_missing' \
  "$TMP_DIR/package-memory-bad-construct-missing-lowering-interface.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-schema.json" \
  > "$TMP_DIR/package-memory-bad-construct-schema.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph schema" >&2
  exit 1
fi
grep -q 'construct_graph.schema must be' \
  "$TMP_DIR/package-memory-bad-construct-schema.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-scalar-metadata.json" \
  > "$TMP_DIR/package-memory-bad-construct-scalar-metadata.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject scalar cardinality aggregate metadata" >&2
  exit 1
fi
grep -q 'construct_graph.cardinality.scalar_edge_metadata' \
  "$TMP_DIR/package-memory-bad-construct-scalar-metadata.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.json" \
  > "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject duplicate scalar cardinality resolution" >&2
  exit 1
fi
grep -q 'construct_graph.cardinality.exactly_one' \
  "$TMP_DIR/package-memory-bad-construct-duplicate-scalar-resolution.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-many-missing-order.json" \
  > "$TMP_DIR/package-memory-bad-construct-many-missing-order.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject many cardinality without order" >&2
  exit 1
fi
grep -q 'construct_graph.cardinality.order_missing' \
  "$TMP_DIR/package-memory-bad-construct-many-missing-order.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.json" \
  > "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject named-many cardinality without resource key" >&2
  exit 1
fi
grep -q 'construct_graph.cardinality.resource_key_missing' \
  "$TMP_DIR/package-memory-bad-construct-named-many-missing-key.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.json" \
  > "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject unknown construct graph edge field" >&2
  exit 1
fi
grep -q 'construct_graph.edge.field_unknown' \
  "$TMP_DIR/package-memory-bad-construct-unknown-edge-field.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph edge evidence collection" >&2
  exit 1
fi
grep -q 'construct_graph.edge.string_array_invalid' \
  "$TMP_DIR/package-memory-bad-construct-edge-evidence-type.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-source-span.json" \
  > "$TMP_DIR/package-memory-bad-construct-source-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph source span" >&2
  exit 1
fi
grep -q 'construct_graph.node.source_span_invalid' \
  "$TMP_DIR/package-memory-bad-construct-source-span.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-span.json" \
  > "$TMP_DIR/package-memory-bad-construct-derived-fact-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph derived fact span" >&2
  exit 1
fi
grep -q 'construct_graph.derived_fact.diagnostic_span_invalid' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-span.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.json" \
  > "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject duplicate construct graph derived fact input refs" >&2
  exit 1
fi
grep -q 'construct_graph.derived_fact.input_refs_invalid' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-input-refs.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.json" \
  > "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph derived fact metadata" >&2
  exit 1
fi
grep -q 'construct_graph.derived_fact.metadata_invalid' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-metadata.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.json" \
  > "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject duplicate construct graph derived facts" >&2
  exit 1
fi
grep -q 'construct_graph.derived_fact.duplicate' \
  "$TMP_DIR/package-memory-bad-construct-derived-fact-duplicate.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-platform-version-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-platform-version-type.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph platform_version" >&2
  exit 1
fi
grep -q 'construct_graph.graph.platform_version_invalid' \
  "$TMP_DIR/package-memory-bad-construct-platform-version-type.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-node-metadata-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-node-metadata-type.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph node metadata" >&2
  exit 1
fi
grep -q 'construct_graph.node.metadata_invalid' \
  "$TMP_DIR/package-memory-bad-construct-node-metadata-type.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph dependency rule_name" >&2
  exit 1
fi
grep -q 'construct_graph.effect_dependency.rule_name_invalid' \
  "$TMP_DIR/package-memory-bad-construct-dependency-rule-name-type.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-span.json" \
  > "$TMP_DIR/package-memory-bad-construct-diagnostic-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph diagnostic span" >&2
  exit 1
fi
grep -q 'construct_graph.diagnostic.source_span_invalid' \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-span.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.json" \
  > "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph diagnostic metadata" >&2
  exit 1
fi
grep -q 'construct_graph.diagnostic.metadata_invalid' \
  "$TMP_DIR/package-memory-bad-construct-diagnostic-metadata.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-diagnostics-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-diagnostics-type.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph diagnostics collection" >&2
  exit 1
fi
grep -q 'construct_graph.diagnostics must be an array' \
  "$TMP_DIR/package-memory-bad-construct-diagnostics-type.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph required interface collection" >&2
  exit 1
fi
grep -q 'construct_graph.interface.collection_invalid' \
  "$TMP_DIR/package-memory-bad-construct-required-interfaces-type.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph provided interface collection" >&2
  exit 1
fi
grep -q 'construct_graph.interface.collection_invalid' \
  "$TMP_DIR/package-memory-bad-construct-provided-interfaces-type.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-interface-phase.json" \
  > "$TMP_DIR/package-memory-bad-construct-interface-phase.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject declared interface phase mismatch" >&2
  exit 1
fi
grep -q 'construct_graph.interface.unsatisfied' \
  "$TMP_DIR/package-memory-bad-construct-interface-phase.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-interface-cardinality.json" \
  > "$TMP_DIR/package-memory-bad-construct-interface-cardinality.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject declared interface cardinality mismatch" >&2
  exit 1
fi
grep -q 'construct_graph.interface.unsatisfied' \
  "$TMP_DIR/package-memory-bad-construct-interface-cardinality.verify.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-interface-type.json" \
  > "$TMP_DIR/package-memory-bad-construct-interface-type.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject invalid construct graph interface type" >&2
  exit 1
fi
grep -q 'construct_graph.interface.type_invalid' \
  "$TMP_DIR/package-memory-bad-construct-interface-type.verify.err"
validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-compile-model-search.json"
validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/scheduled-escalation-compile-model-search.json"
validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/provider-language-compile-model-search.json"
validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/terminal-output-compile-model-search.json"
validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/package-memory-check-model-search.json"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-bad-report-schema.json" \
  2> "$TMP_DIR/event-bridge-model-search-bad-report-schema.err"; then
  echo "expected model-search validator to reject schema-invalid report envelope" >&2
  exit 1
fi
grep -q 'compile report failed schema validation against compile_report_v0.schema.json' \
  "$TMP_DIR/event-bridge-model-search-bad-report-schema.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-bad-ir-predicate.json" \
  2> "$TMP_DIR/event-bridge-model-search-bad-ir-predicate.err"; then
  echo "expected model-search validator to reject unknown generated IR predicate" >&2
  exit 1
fi
grep -q 'unknown generated predicate' \
  "$TMP_DIR/event-bridge-model-search-bad-ir-predicate.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-bad-ir-predicate.json" \
  > "$TMP_DIR/event-bridge-model-search-bad-ir-predicate.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject unknown generated IR predicate" >&2
  exit 1
fi
grep -q 'unknown generated predicate' \
  "$TMP_DIR/event-bridge-model-search-bad-ir-predicate.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-stale-ir-obligations.json" \
  2> "$TMP_DIR/event-bridge-model-search-stale-ir-obligations.err"; then
  echo "expected model-search validator to reject stale IR obligation artifact" >&2
  exit 1
fi
grep -q 'IR obligation mismatch' \
  "$TMP_DIR/event-bridge-model-search-stale-ir-obligations.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-stale-ir-obligations.json" \
  > "$TMP_DIR/event-bridge-model-search-stale-ir-obligations.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject stale IR obligation artifact" >&2
  exit 1
fi
grep -q 'model_search IR obligation mismatch' \
  "$TMP_DIR/event-bridge-model-search-stale-ir-obligations.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-missing-ir-obligation.json" \
  2> "$TMP_DIR/event-bridge-model-search-missing-ir-obligation.err"; then
  echo "expected model-search validator to reject missing generated IR obligation" >&2
  exit 1
fi
grep -q 'snapshot implies' \
  "$TMP_DIR/event-bridge-model-search-missing-ir-obligation.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-missing-ir-obligation.json" \
  > "$TMP_DIR/event-bridge-model-search-missing-ir-obligation.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject missing generated IR obligation" >&2
  exit 1
fi
grep -q 'snapshot implies' \
  "$TMP_DIR/event-bridge-model-search-missing-ir-obligation.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-predicate-counts.json" \
  2> "$TMP_DIR/event-bridge-model-search-wrong-ir-predicate-counts.err"; then
  echo "expected model-search validator to reject wrong IR predicate counts" >&2
  exit 1
fi
grep -q 'IR predicate counts' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-predicate-counts.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-predicate-counts.json" \
  > "$TMP_DIR/event-bridge-model-search-wrong-ir-predicate-counts.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong IR predicate counts" >&2
  exit 1
fi
grep -q 'IR predicate counts' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-predicate-counts.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-endpoint-counts.json" \
  2> "$TMP_DIR/event-bridge-model-search-wrong-ir-endpoint-counts.err"; then
  echo "expected model-search validator to reject wrong IR endpoint counts" >&2
  exit 1
fi
grep -q 'IR endpoint counts' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-endpoint-counts.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-endpoint-counts.json" \
  > "$TMP_DIR/event-bridge-model-search-wrong-ir-endpoint-counts.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong IR endpoint counts" >&2
  exit 1
fi
grep -q 'IR endpoint counts' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-endpoint-counts.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-outcome-counts.json" \
  2> "$TMP_DIR/event-bridge-model-search-wrong-ir-outcome-counts.err"; then
  echo "expected model-search validator to reject wrong IR outcome counts" >&2
  exit 1
fi
grep -q 'IR outcome counts' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-outcome-counts.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-outcome-counts.json" \
  > "$TMP_DIR/event-bridge-model-search-wrong-ir-outcome-counts.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong IR outcome counts" >&2
  exit 1
fi
grep -q 'IR outcome counts' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-outcome-counts.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-sequence.json" \
  2> "$TMP_DIR/event-bridge-model-search-wrong-ir-sequence.err"; then
  echo "expected model-search validator to reject wrong IR obligation sequence" >&2
  exit 1
fi
grep -q 'IR obligation sequence' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-sequence.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-sequence.json" \
  > "$TMP_DIR/event-bridge-model-search-wrong-ir-sequence.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong IR obligation sequence" >&2
  exit 1
fi
grep -q 'IR obligation sequence' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-sequence.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-description.json" \
  2> "$TMP_DIR/event-bridge-model-search-wrong-ir-description.err"; then
  echo "expected model-search validator to reject wrong IR obligation description" >&2
  exit 1
fi
grep -q 'IR obligation descriptions' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-description.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-description.json" \
  > "$TMP_DIR/event-bridge-model-search-wrong-ir-description.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong IR obligation description" >&2
  exit 1
fi
grep -q 'IR obligation descriptions' \
  "$TMP_DIR/event-bridge-model-search-wrong-ir-description.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/provider-language-model-search-wrong-dependency-source-span.json" \
  2> "$TMP_DIR/provider-language-model-search-wrong-dependency-source-span.err"; then
  echo "expected model-search validator to reject wrong dependency source span" >&2
  exit 1
fi
grep -q 'IR dependency obligation source_span mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-dependency-source-span.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/provider-language-model-search-wrong-dependency-source-span.json" \
  > "$TMP_DIR/provider-language-model-search-wrong-dependency-source-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong dependency source span" >&2
  exit 1
fi
grep -q 'IR dependency obligation.*source_span mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-dependency-source-span.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-wrong-handoff-source-span.json" \
  2> "$TMP_DIR/event-bridge-model-search-wrong-handoff-source-span.err"; then
  echo "expected model-search validator to reject wrong handoff source span" >&2
  exit 1
fi
grep -q 'artifact obligation mismatch for artifact.lowered_ir.*source_span' \
  "$TMP_DIR/event-bridge-model-search-wrong-handoff-source-span.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-wrong-handoff-source-span.json" \
  > "$TMP_DIR/event-bridge-model-search-wrong-handoff-source-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong handoff source span" >&2
  exit 1
fi
grep -q 'model_search artifact obligation mismatch.*artifact.lowered_ir.*source_span' \
  "$TMP_DIR/event-bridge-model-search-wrong-handoff-source-span.verify.err"
validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/package-memory-model-search-wrong-dependency-source-span-with-graph.json"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-model-search-wrong-dependency-source-span-with-graph.json" \
  > "$TMP_DIR/package-memory-model-search-wrong-dependency-source-span-with-graph.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject package wrong dependency source span even when graph evidence agrees" >&2
  exit 1
fi
grep -q 'source-backed construct_graph mismatch' \
  "$TMP_DIR/package-memory-model-search-wrong-dependency-source-span-with-graph.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/provider-language-model-search-wrong-assertion-source-span.json" \
  2> "$TMP_DIR/provider-language-model-search-wrong-assertion-source-span.err"; then
  echo "expected model-search validator to reject wrong assertion source span" >&2
  exit 1
fi
grep -q 'IR assertion obligation source_span mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-assertion-source-span.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/provider-language-model-search-wrong-assertion-source-span.json" \
  > "$TMP_DIR/provider-language-model-search-wrong-assertion-source-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong assertion source span" >&2
  exit 1
fi
grep -q 'IR assertion obligation.*source_span mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-assertion-source-span.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/provider-language-model-search-wrong-revision-source-span.json" \
  2> "$TMP_DIR/provider-language-model-search-wrong-revision-source-span.err"; then
  echo "expected model-search validator to reject wrong revision source span" >&2
  exit 1
fi
grep -q 'IR revision .* obligation source_span mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-revision-source-span.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/provider-language-model-search-wrong-revision-source-span.json" \
  > "$TMP_DIR/provider-language-model-search-wrong-revision-source-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong revision source span" >&2
  exit 1
fi
grep -q 'IR revision .* obligation.*source_span mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-revision-source-span.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/provider-language-model-search-wrong-guard-source-span.json" \
  2> "$TMP_DIR/provider-language-model-search-wrong-guard-source-span.err"; then
  echo "expected model-search validator to reject wrong guard source span" >&2
  exit 1
fi
grep -q 'IR guard obligation source_span mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-guard-source-span.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/provider-language-model-search-wrong-guard-source-span.json" \
  > "$TMP_DIR/provider-language-model-search-wrong-guard-source-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong guard source span" >&2
  exit 1
fi
grep -q 'IR guard obligation.*source_span mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-guard-source-span.verify.err"
validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/provider-language-model-search-wrong-guard-source-span-with-anchor.json"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/provider-language-model-search-wrong-guard-source-span-with-anchor.json" \
  > "$TMP_DIR/provider-language-model-search-wrong-guard-source-span-with-anchor.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong guard source span even when the report anchor agrees" >&2
  exit 1
fi
grep -q 'source-backed construct_graph mismatch' \
  "$TMP_DIR/provider-language-model-search-wrong-guard-source-span-with-anchor.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/terminal-output-model-search-wrong-terminal-source-span.json" \
  2> "$TMP_DIR/terminal-output-model-search-wrong-terminal-source-span.err"; then
  echo "expected model-search validator to reject wrong terminal source span" >&2
  exit 1
fi
grep -q 'IR terminal branch obligation source_span mismatch' \
  "$TMP_DIR/terminal-output-model-search-wrong-terminal-source-span.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/terminal-output-model-search-wrong-terminal-source-span.json" \
  > "$TMP_DIR/terminal-output-model-search-wrong-terminal-source-span.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject wrong terminal source span" >&2
  exit 1
fi
grep -q 'IR terminal branch obligation.*source_span mismatch' \
  "$TMP_DIR/terminal-output-model-search-wrong-terminal-source-span.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-unsupported-ir-obligation.json" \
  2> "$TMP_DIR/event-bridge-model-search-unsupported-ir-obligation.err"; then
  echo "expected model-search validator to reject unsupported IR obligation" >&2
  exit 1
fi
grep -q 'not supported by the embedded snapshot' \
  "$TMP_DIR/event-bridge-model-search-unsupported-ir-obligation.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-unsupported-ir-obligation.json" \
  > "$TMP_DIR/event-bridge-model-search-unsupported-ir-obligation.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject unsupported IR obligation" >&2
  exit 1
fi
grep -q 'not supported by the embedded snapshot' \
  "$TMP_DIR/event-bridge-model-search-unsupported-ir-obligation.verify.err"
if validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/event-bridge-model-search-stale-construct-evidence.json" \
  2> "$TMP_DIR/event-bridge-model-search-stale-construct-evidence.err"; then
  echo "expected model-search validator to reject stale construct graph evidence" >&2
  exit 1
fi
grep -q 'derived_facts validator predicate input_refs incomplete' \
  "$TMP_DIR/event-bridge-model-search-stale-construct-evidence.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/event-bridge-model-search-stale-construct-evidence.json" \
  > "$TMP_DIR/event-bridge-model-search-stale-construct-evidence.verify.err" \
  2>&1; then
  echo "expected whip verify-report to reject stale model-search construct graph evidence" >&2
  exit 1
fi
grep -q 'construct graph validator predicate' \
  "$TMP_DIR/event-bridge-model-search-stale-construct-evidence.verify.err"
construct_graph_to_maude \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-construct.maude"
construct_graph_to_maude \
  "$TMP_DIR/compile-verified-construct-graph.json" \
  > "$TMP_DIR/compile-verified-construct-graph.maude"
lowered_ir_to_maude \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-lowered.maude"
lowered_ir_to_maude \
  "$TMP_DIR/compile-verified-lowered-ir.json" \
  > "$TMP_DIR/compile-verified-lowered-ir.maude"
construct_graph_to_maude \
  "$TMP_DIR/event-bridge-compile.json" \
  > "$TMP_DIR/event-bridge-construct.maude"
lowered_ir_to_maude \
  "$TMP_DIR/event-bridge-compile.json" \
  > "$TMP_DIR/event-bridge-lowered.maude"
# `event-bridge` declares + cross-emits a signal but has no `source` block, so it
# no longer produces a signal_source admission node. Bridge coverage for
# signal_source/clock_source handoff entrypoints lives in the Rust lowered-IR
# bridge tests and the source-block model-search fixtures.
grep -q 'assertionEntrypoint' "$TMP_DIR/event-bridge-lowered.maude"
construct_graph_to_maude \
  "$TMP_DIR/scheduled-escalation-compile.json" \
  > "$TMP_DIR/scheduled-escalation-construct.maude"
lowered_ir_to_maude \
  "$TMP_DIR/scheduled-escalation-compile.json" \
  > "$TMP_DIR/scheduled-escalation-lowered.maude"
grep -q 'scheduleEntrypoint' "$TMP_DIR/scheduled-escalation-lowered.maude"
if env -u WHIPPLESCRIPT_PLATFORM_CATALOG_PATH \
  python3 scripts/construct-graph-to-maude.py \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-artifacts-missing-verifier-catalog-construct.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-missing-verifier-catalog-construct.err"; then
  echo "expected construct graph bridge to require an explicit verifier platform catalog" >&2
  exit 1
fi
grep -q 'WHIPPLESCRIPT_PLATFORM_CATALOG_PATH is required' \
  "$TMP_DIR/compile-verified-artifacts-missing-verifier-catalog-construct.err"
if env -u WHIPPLESCRIPT_PLATFORM_CATALOG_PATH \
  python3 scripts/lowered-ir-to-maude.py \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-artifacts-missing-verifier-catalog-lowered.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-missing-verifier-catalog-lowered.err"; then
  echo "expected lowered IR bridge to require an explicit verifier platform catalog" >&2
  exit 1
fi
grep -q 'WHIPPLESCRIPT_PLATFORM_CATALOG_PATH is required' \
  "$TMP_DIR/compile-verified-artifacts-missing-verifier-catalog-lowered.err"
env -u WHIPPLESCRIPT_PLATFORM_CATALOG_PATH \
  python3 scripts/construct-graph-to-maude.py \
  --platform-catalog "$PLATFORM_CATALOG_PATH" \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-artifacts-explicit-catalog-construct.maude"
env -u WHIPPLESCRIPT_PLATFORM_CATALOG_PATH \
  python3 scripts/lowered-ir-to-maude.py \
  --platform-catalog "$PLATFORM_CATALOG_PATH" \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-artifacts-explicit-catalog-lowered.maude"
env -u WHIPPLESCRIPT_PLATFORM_CATALOG_PATH \
  python3 scripts/validate-artifact-reports.py \
  --platform-catalog "$PLATFORM_CATALOG_PATH" \
  "$TMP_DIR/compile-verified-construct-graph.json" \
  "$TMP_DIR/compile-verified-artifacts.json"
python3 - "$PLATFORM_CATALOG_PATH" "$TMP_DIR/duplicate-id-platform-construct-catalog.json" <<'PY'
import copy
import json
import sys

catalog = json.load(open(sys.argv[1]))
duplicate = copy.deepcopy(catalog["lowerings"][0])
duplicate["provided_interfaces"] = []
catalog["lowerings"].append(duplicate)
with open(sys.argv[2], "w") as handle:
    json.dump(catalog, handle)
PY
if env -u WHIPPLESCRIPT_PLATFORM_CATALOG_PATH \
  python3 scripts/construct-graph-to-maude.py \
  --platform-catalog "$TMP_DIR/duplicate-id-platform-construct-catalog.json" \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-artifacts-duplicate-id-catalog-construct.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-duplicate-id-catalog-construct.err"; then
  echo "expected construct graph bridge to reject duplicate verifier catalog lowering ids" >&2
  exit 1
fi
grep -q 'lowerings duplicates id' \
  "$TMP_DIR/compile-verified-artifacts-duplicate-id-catalog-construct.err"
if env -u WHIPPLESCRIPT_PLATFORM_CATALOG_PATH \
  python3 scripts/lowered-ir-to-maude.py \
  --platform-catalog "$TMP_DIR/duplicate-id-platform-construct-catalog.json" \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-artifacts-duplicate-id-catalog-lowered.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-duplicate-id-catalog-lowered.err"; then
  echo "expected lowered IR bridge to reject duplicate verifier catalog lowering ids" >&2
  exit 1
fi
grep -q 'lowerings duplicates id' \
  "$TMP_DIR/compile-verified-artifacts-duplicate-id-catalog-lowered.err"
python3 - "$TMP_DIR/compile-verified-artifacts.json" "$TMP_DIR/compile-verified-artifacts-bad-package-contract.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["entries"][0]["package_contract"]["package_contract_digest"] = "0" * 64
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if construct_graph_to_maude \
  "$TMP_DIR/compile-verified-artifacts-bad-package-contract.json" \
  > "$TMP_DIR/compile-verified-artifacts-bad-package-contract-construct.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-bad-package-contract-construct.err"; then
  echo "expected construct graph bridge to reject stale verified artifact package contract" >&2
  exit 1
fi
grep -q 'package_contract.package_contract_digest does not match' \
  "$TMP_DIR/compile-verified-artifacts-bad-package-contract-construct.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-verified-artifacts-bad-package-contract.json" \
  > "$TMP_DIR/compile-verified-artifacts-bad-package-contract-lowered.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-bad-package-contract-lowered.err"; then
  echo "expected lowered IR bridge to reject stale verified artifact package contract" >&2
  exit 1
fi
grep -q 'package_contract.package_contract_digest does not match' \
  "$TMP_DIR/compile-verified-artifacts-bad-package-contract-lowered.err"
python3 - "$PLATFORM_CATALOG_PATH" "$TMP_DIR/stale-platform-construct-catalog.json" <<'PY'
import json
import sys

catalog = json.load(open(sys.argv[1]))
catalog["interface_kinds"].append("BogusInterface")
with open(sys.argv[2], "w") as handle:
    json.dump(catalog, handle)
PY
if WHIPPLESCRIPT_PLATFORM_CATALOG_PATH="$TMP_DIR/stale-platform-construct-catalog.json" \
  python3 scripts/construct-graph-to-maude.py \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-artifacts-stale-verifier-catalog-construct.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-stale-verifier-catalog-construct.err"; then
  echo "expected construct graph bridge to reject stale verifier platform catalog" >&2
  exit 1
fi
grep -q 'platform_construct_catalog must match verifier platform catalog' \
  "$TMP_DIR/compile-verified-artifacts-stale-verifier-catalog-construct.err"
if WHIPPLESCRIPT_PLATFORM_CATALOG_PATH="$TMP_DIR/stale-platform-construct-catalog.json" \
  python3 scripts/lowered-ir-to-maude.py \
  "$TMP_DIR/compile-verified-artifacts.json" \
  > "$TMP_DIR/compile-verified-artifacts-stale-verifier-catalog-lowered.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-stale-verifier-catalog-lowered.err"; then
  echo "expected lowered IR bridge to reject stale verifier platform catalog" >&2
  exit 1
fi
grep -q 'platform_construct_catalog must match verifier platform catalog' \
  "$TMP_DIR/compile-verified-artifacts-stale-verifier-catalog-lowered.err"
WHIPPLESCRIPT_PLATFORM_CATALOG_PATH="$TMP_DIR/stale-platform-construct-catalog.json" \
  cargo run --quiet -p whipplescript -- --json check \
  --model-search \
  examples/package-memory.whip \
  > "$TMP_DIR/package-memory-check-model-search-stale-inherited-catalog.json"
validate_model_search_reports \
  --require-model-search \
  --require-ok \
  "$TMP_DIR/package-memory-check-model-search-stale-inherited-catalog.json"
cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-check-model-search-stale-inherited-catalog.json"
python3 - "$TMP_DIR/compile-verified-artifacts.json" "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog.json" <<'PY'
import hashlib
import json
import sys


def canonical_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


report = json.load(open(sys.argv[1]))
entry = report["entries"][0]
entry["package_contract"]["platform_construct_catalog"]["interface_kinds"].append("BogusInterface")
body = dict(entry["package_contract"])
body.pop("package_contract_digest", None)
digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
entry["package_contract"]["package_contract_digest"] = digest
entry["construct_graph"]["package_contract_digest"] = digest
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if construct_graph_to_maude \
  "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog.json" \
  > "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog-construct.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog-construct.err"; then
  echo "expected construct graph bridge to reject stale verified artifact platform catalog" >&2
  exit 1
fi
grep -q 'platform_construct_catalog must match verifier platform catalog' \
  "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog-construct.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog.json" \
  > "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog-lowered.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog-lowered.err"; then
  echo "expected lowered IR bridge to reject stale verified artifact platform catalog" >&2
  exit 1
fi
grep -q 'platform_construct_catalog must match verifier platform catalog' \
  "$TMP_DIR/compile-verified-artifacts-bad-platform-catalog-lowered.err"
python3 - "$TMP_DIR/compile-verified-artifacts.json" "$TMP_DIR/compile-verified-artifacts-bad-program-digest.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["entries"][0]["lowered_ir_report"]["accepted_program_digest"] = "0" * 64
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if lowered_ir_to_maude \
  "$TMP_DIR/compile-verified-artifacts-bad-program-digest.json" \
  > "$TMP_DIR/compile-verified-artifacts-bad-program-digest.maude" \
  2> "$TMP_DIR/compile-verified-artifacts-bad-program-digest.err"; then
  echo "expected lowered IR bridge to reject stale accepted program digest" >&2
  exit 1
fi
grep -q 'accepted_program_digest does not match' \
  "$TMP_DIR/compile-verified-artifacts-bad-program-digest.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-construct-evidence.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
for fact in report["construct_graph"]["derived_facts"]:
    if fact.get("owner_subsystem") == "construct_graph_validator":
        fact["input_refs"].append("stale-construct-ref")
        break
else:
    raise SystemExit("compile construct graph did not contain validator-owned facts")
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-construct-evidence.json" \
  2> "$TMP_DIR/compile-bad-construct-evidence.err"; then
  echo "expected artifact report validator to reject stale construct graph evidence" >&2
  exit 1
fi
grep -q 'construct graph derived_facts validator predicate input_refs unexpected' \
  "$TMP_DIR/compile-bad-construct-evidence.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-construct-evidence.json" \
  > "$TMP_DIR/compile-bad-construct-evidence-lowered.maude" \
  2> "$TMP_DIR/compile-bad-construct-evidence-lowered.err"; then
  echo "expected lowered IR bridge to reject stale construct graph evidence" >&2
  exit 1
fi
grep -q 'construct graph derived_facts validator predicate input_refs unexpected' \
  "$TMP_DIR/compile-bad-construct-evidence-lowered.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-construct-evidence.json" \
  2> "$TMP_DIR/compile-bad-construct-evidence-rust.err"; then
  echo "expected whip verify-report to reject stale construct graph evidence" >&2
  exit 1
fi
grep -q 'construct graph validator predicate' \
  "$TMP_DIR/compile-bad-construct-evidence-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-stale-lowered-version.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["lowered_ir_report"]["lowerer_version"] = "whipplescript:stale"
for fact in report["lowered_ir_report"]["derived_facts"]:
    if fact.get("predicate", "").startswith((
        "lowered_ir.validator.graph.deterministic:",
        "lowered_ir.validator.graph.report_complete:",
    )):
        fact["input_refs"] = [
            "lowered_ir.root.lowerer_version:whipplescript:stale"
            if isinstance(ref, str)
            and ref.startswith("lowered_ir.root.lowerer_version:")
            else ref
            for ref in fact.get("input_refs", [])
        ]
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
validate_artifact_reports \
  "$TMP_DIR/compile-stale-lowered-version.json"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-stale-lowered-version.json" \
  2> "$TMP_DIR/compile-stale-lowered-version-rust.err"; then
  echo "expected whip verify-report to reject stale lowered IR re-emission" >&2
  exit 1
fi
grep -q 'source-backed lowered_ir_report mismatch' \
  "$TMP_DIR/compile-stale-lowered-version-rust.err"

python3 - "$TMP_DIR/package-memory-check.json" "$TMP_DIR/package-memory-bad-construct-provider.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
entry = report[0] if isinstance(report, list) else report
graph = entry["construct_graph"]
if not graph.get("edges"):
    raise SystemExit("construct graph fixture did not contain an edge")
edge = graph["edges"][0]
edge_ref = f"{edge['required_port_id']}->{edge['provided_port_id']}"
old_provider = edge["provider_node_id"]
new_provider = "__spoofed_provider__"
edge["provider_node_id"] = new_provider
edge_predicates = {
    f"validator.edge.endpoints_valid:{edge_ref}",
    f"validator.edge.kind_compatible:{edge_ref}",
    f"validator.edge.type_compatible:{edge_ref}",
    f"validator.edge.phase_compatible:{edge_ref}",
    f"validator.edge.version_compatible:{edge_ref}",
    f"validator.edge.resource_compatible:{edge_ref}",
}
for fact in graph["derived_facts"]:
    if fact.get("predicate") in edge_predicates:
        fact["input_refs"] = [
            new_provider if ref == old_provider else ref
            for ref in fact["input_refs"]
        ]
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/package-memory-bad-construct-provider.json" \
  2> "$TMP_DIR/package-memory-bad-construct-provider.err"; then
  echo "expected artifact report validator to reject spoofed construct graph provider" >&2
  exit 1
fi
grep -q 'references missing provider node' \
  "$TMP_DIR/package-memory-bad-construct-provider.err"
if lowered_ir_to_maude \
  "$TMP_DIR/package-memory-bad-construct-provider.json" \
  > "$TMP_DIR/package-memory-bad-construct-provider-lowered.maude" \
  2> "$TMP_DIR/package-memory-bad-construct-provider-lowered.err"; then
  echo "expected lowered IR bridge to reject spoofed construct graph provider" >&2
  exit 1
fi
grep -q 'references missing provider node' \
  "$TMP_DIR/package-memory-bad-construct-provider-lowered.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/package-memory-bad-construct-provider.json" \
  2> "$TMP_DIR/package-memory-bad-construct-provider-rust.err"; then
  echo "expected whip verify-report to reject spoofed construct graph provider" >&2
  exit 1
fi
grep -q 'provider_node_missing' \
  "$TMP_DIR/package-memory-bad-construct-provider-rust.err"

if validate_artifact_reports \
  "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary.json" \
  2> "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary.err"; then
  echo "expected artifact report validator to reject unknown construct graph output vocabulary" >&2
  exit 1
fi
grep -Eq "unknown core object kind|is not one of" \
  "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary.err"
if construct_graph_to_maude \
  "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary.json" \
  > "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary.maude" \
  2> "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary.bridge.err"; then
  echo "expected construct graph bridge to reject unknown output vocabulary" >&2
  exit 1
fi
grep -Eq "unknown core object kind|is not one of" \
  "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary.json" \
  2> "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary-rust.err"; then
  echo "expected whip verify-report to reject unknown construct graph output vocabulary" >&2
  exit 1
fi
grep -q 'construct_graph.node.output_kind_unknown' \
  "$TMP_DIR/compile-bad-construct-unknown-output-vocabulary-rust.err"

if validate_artifact_reports \
  "$TMP_DIR/compile-bad-construct-lifecycle-profile.json" \
  2> "$TMP_DIR/compile-bad-construct-lifecycle-profile.err"; then
  echo "expected artifact report validator to reject construct graph lifecycle profile mismatch" >&2
  exit 1
fi
grep -q 'requires lifecycle profile' \
  "$TMP_DIR/compile-bad-construct-lifecycle-profile.err"
if construct_graph_to_maude \
  "$TMP_DIR/compile-bad-construct-lifecycle-profile.json" \
  > "$TMP_DIR/compile-bad-construct-lifecycle-profile.maude" \
  2> "$TMP_DIR/compile-bad-construct-lifecycle-profile.bridge.err"; then
  echo "expected construct graph bridge to reject lifecycle profile mismatch" >&2
  exit 1
fi
grep -q 'requires lifecycle profile' \
  "$TMP_DIR/compile-bad-construct-lifecycle-profile.bridge.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-construct-lifecycle-profile.json" \
  > "$TMP_DIR/compile-bad-construct-lifecycle-profile-lowered.maude" \
  2> "$TMP_DIR/compile-bad-construct-lifecycle-profile-lowered.err"; then
  echo "expected lowered IR bridge to reject lifecycle profile mismatch" >&2
  exit 1
fi
grep -q 'requires lifecycle profile' \
  "$TMP_DIR/compile-bad-construct-lifecycle-profile-lowered.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-construct-lifecycle-profile.json" \
  2> "$TMP_DIR/compile-bad-construct-lifecycle-profile-rust.err"; then
  echo "expected whip verify-report to reject construct graph lifecycle profile mismatch" >&2
  exit 1
fi
grep -q 'construct_graph.node.lifecycle_profile_mismatch' \
  "$TMP_DIR/compile-bad-construct-lifecycle-profile-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-package-contract.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["package_contract"]["package_contract_digest"] = "0" * 64
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-package-contract.json" \
  2> "$TMP_DIR/compile-bad-package-contract.err"; then
  echo "expected artifact report validator to reject stale package contract" >&2
  exit 1
fi
grep -q 'package_contract.package_contract_digest does not match' \
  "$TMP_DIR/compile-bad-package-contract.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-package-contract.json" \
  2> "$TMP_DIR/compile-bad-package-contract-rust.err"; then
  echo "expected whip verify-report to reject stale package contract" >&2
  exit 1
fi
grep -q 'package_contract.package_contract_digest does not match' \
  "$TMP_DIR/compile-bad-package-contract-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-reordered-package-contract.json" <<'PY'
import json
import sys


def reversed_objects(value):
    if isinstance(value, dict):
        return {key: reversed_objects(value[key]) for key in reversed(list(value.keys()))}
    if isinstance(value, list):
        return [reversed_objects(item) for item in value]
    return value


report = json.load(open(sys.argv[1]))
report["package_contract"] = reversed_objects(report["package_contract"])
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
validate_artifact_reports \
  "$TMP_DIR/compile-reordered-package-contract.json"
cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-reordered-package-contract.json"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-package-contract-diagnostics.json" <<'PY'
import hashlib
import json
import sys


def canonical_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


report = json.load(open(sys.argv[1]))
report["package_contract"]["diagnostics"].append({
    "code": "package_contract.synthetic",
    "message": "synthetic package contract diagnostic",
})
body = dict(report["package_contract"])
body.pop("package_contract_digest", None)
digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
report["package_contract"]["package_contract_digest"] = digest
report["construct_graph"]["package_contract_digest"] = digest
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-package-contract-diagnostics.json" \
  2> "$TMP_DIR/compile-package-contract-diagnostics.err"; then
  echo "expected artifact report validator to reject package contract diagnostics" >&2
  exit 1
fi
grep -q 'package_contract.diagnostics must be empty' \
  "$TMP_DIR/compile-package-contract-diagnostics.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-package-contract-diagnostics.json" \
  2> "$TMP_DIR/compile-package-contract-diagnostics-rust.err"; then
  echo "expected whip verify-report to reject package contract diagnostics" >&2
  exit 1
fi
grep -q 'package_contract.diagnostics must be empty' \
  "$TMP_DIR/compile-package-contract-diagnostics-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-platform-catalog.json" <<'PY'
import hashlib
import json
import sys


def canonical_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


report = json.load(open(sys.argv[1]))
report["package_contract"]["platform_construct_catalog"]["interface_kinds"].append("BogusInterface")
body = dict(report["package_contract"])
body.pop("package_contract_digest", None)
digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
report["package_contract"]["package_contract_digest"] = digest
report["construct_graph"]["package_contract_digest"] = digest
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-platform-catalog.json" \
  2> "$TMP_DIR/compile-bad-platform-catalog.err"; then
  echo "expected artifact report validator to reject stale platform catalog" >&2
  exit 1
fi
grep -q 'platform_construct_catalog must match verifier platform catalog' \
  "$TMP_DIR/compile-bad-platform-catalog.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-platform-catalog.json" \
  2> "$TMP_DIR/compile-bad-platform-catalog-rust.err"; then
  echo "expected whip verify-report to reject stale platform catalog" >&2
  exit 1
fi
grep -q 'platform_construct_catalog must match verifier platform catalog' \
  "$TMP_DIR/compile-bad-platform-catalog-rust.err"

if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-output-vocabulary.json" \
  2> "$TMP_DIR/compile-bad-lowered-output-vocabulary.err"; then
  echo "expected artifact report validator to reject stale lowered output vocabulary" >&2
  exit 1
fi
grep -q 'not allowed by construct graph output vocabulary' \
  "$TMP_DIR/compile-bad-lowered-output-vocabulary.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-output-vocabulary.json" \
  > "$TMP_DIR/compile-bad-lowered-output-vocabulary.maude" \
  2> "$TMP_DIR/compile-bad-lowered-output-vocabulary.bridge.err"; then
  echo "expected lowered IR bridge to reject stale lowered output vocabulary" >&2
  exit 1
fi
grep -q 'not allowed by construct graph output vocabulary' \
  "$TMP_DIR/compile-bad-lowered-output-vocabulary.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-output-vocabulary.json" \
  2> "$TMP_DIR/compile-bad-lowered-output-vocabulary-rust.err"; then
  echo "expected whip verify-report to reject stale lowered output vocabulary" >&2
  exit 1
fi
grep -Eq 'output_kind_unallowed|runtime_entrypoint_unallowed|source-backed lowered_ir_report mismatch|source-backed construct_graph mismatch' \
  "$TMP_DIR/compile-bad-lowered-output-vocabulary-rust.err"

if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-schema.json" \
  2> "$TMP_DIR/compile-bad-lowered-schema.err"; then
  echo "expected artifact report validator to reject invalid lowered IR schema" >&2
  exit 1
fi
grep -Eq 'was expected|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-schema.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-schema.json" \
  > "$TMP_DIR/compile-bad-lowered-schema.maude" \
  2> "$TMP_DIR/compile-bad-lowered-schema.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR schema" >&2
  exit 1
fi
grep -Eq 'was expected|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-schema.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-schema.json" \
  2> "$TMP_DIR/compile-bad-lowered-schema-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR schema" >&2
  exit 1
fi
grep -q 'lowered_ir_report.schema must be' \
  "$TMP_DIR/compile-bad-lowered-schema-rust.err"
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-lowerer-version-type.json" \
  2> "$TMP_DIR/compile-bad-lowered-lowerer-version-type.err"; then
  echo "expected artifact report validator to reject invalid lowered IR lowerer_version" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/compile-bad-lowered-lowerer-version-type.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-lowerer-version-type.json" \
  > "$TMP_DIR/compile-bad-lowered-lowerer-version-type.maude" \
  2> "$TMP_DIR/compile-bad-lowered-lowerer-version-type.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR lowerer_version" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not of type' \
  "$TMP_DIR/compile-bad-lowered-lowerer-version-type.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-lowerer-version-type.json" \
  2> "$TMP_DIR/compile-bad-lowered-lowerer-version-type-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR lowerer_version" >&2
  exit 1
fi
grep -q 'lowered_ir.report.lowerer_version_invalid' \
  "$TMP_DIR/compile-bad-lowered-lowerer-version-type-rust.err"
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-preserved-predicate-type.json" \
  2> "$TMP_DIR/compile-bad-lowered-preserved-predicate-type.err"; then
  echo "expected artifact report validator to reject invalid lowered IR preserved_predicate" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not one of|is not of type' \
  "$TMP_DIR/compile-bad-lowered-preserved-predicate-type.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-preserved-predicate-type.json" \
  > "$TMP_DIR/compile-bad-lowered-preserved-predicate-type.maude" \
  2> "$TMP_DIR/compile-bad-lowered-preserved-predicate-type.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR preserved_predicate" >&2
  exit 1
fi
grep -Eq 'not valid under any|is not one of|is not of type' \
  "$TMP_DIR/compile-bad-lowered-preserved-predicate-type.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-preserved-predicate-type.json" \
  2> "$TMP_DIR/compile-bad-lowered-preserved-predicate-type-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR preserved_predicate" >&2
  exit 1
fi
grep -q 'lowered_ir.dependency.preserved_predicate_invalid' \
  "$TMP_DIR/compile-bad-lowered-preserved-predicate-type-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-evidence.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
for fact in report["lowered_ir_report"]["derived_facts"]:
    if fact.get("owner_subsystem") == "lowered_ir_validator":
        fact["input_refs"].append("stale-lowered-ref")
        break
else:
    raise SystemExit("compile lowered IR report did not contain validator-owned facts")
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-evidence.json" \
  2> "$TMP_DIR/compile-bad-lowered-evidence.err"; then
  echo "expected artifact report validator to reject stale lowered IR evidence" >&2
  exit 1
fi
grep -q 'lowered IR report derived_facts validator predicate input_refs unexpected' \
  "$TMP_DIR/compile-bad-lowered-evidence.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-evidence.json" \
  2> "$TMP_DIR/compile-bad-lowered-evidence-rust.err"; then
  echo "expected whip verify-report to reject stale lowered IR evidence" >&2
  exit 1
fi
grep -q 'lowered IR report validator predicate' \
  "$TMP_DIR/compile-bad-lowered-evidence-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-owner.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
graph_id = lowered["graph_id"]
core_objects = lowered["core_objects"]
target = next(
    obj for obj in core_objects
    if obj.get("owner_kind") == "node" and obj.get("owner_ref")
)
object_id = target["object_id"]
old_owner_ref = target["owner_ref"]
new_owner_ref = "__spoofed_owner__"
target["owner_ref"] = new_owner_ref
owner_refs = [graph_id]
for obj in core_objects:
    owner_refs.extend([obj["object_id"], obj["owner_kind"], obj["owner_ref"]])
owner_refs = list(dict.fromkeys(owner_refs))
old_owner_predicate = (
    f"lowered_ir.validator.core_object.owner:{object_id}:node:{old_owner_ref}"
)
new_owner_predicate = (
    f"lowered_ir.validator.core_object.owner:{object_id}:node:{new_owner_ref}"
)
for fact in lowered["derived_facts"]:
    if fact.get("predicate") == old_owner_predicate:
        fact["predicate"] = new_owner_predicate
        fact["input_refs"] = [graph_id, object_id, "node", new_owner_ref]
    if fact.get("predicate") == f"lowered_ir.validator.graph.owner_unique:{graph_id}":
        fact["input_refs"] = owner_refs
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-owner.json" \
  2> "$TMP_DIR/compile-bad-lowered-owner.err"; then
  echo "expected artifact report validator to reject spoofed lowered IR owner" >&2
  exit 1
fi
grep -q 'references unknown owner node' \
  "$TMP_DIR/compile-bad-lowered-owner.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-owner.json" \
  2> "$TMP_DIR/compile-bad-lowered-owner-rust.err"; then
  echo "expected whip verify-report to reject spoofed lowered IR owner" >&2
  exit 1
fi
grep -q 'owner_unknown' \
  "$TMP_DIR/compile-bad-lowered-owner-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-entrypoint-refs.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
target = next(
    obj for obj in lowered["core_objects"]
    if obj.get("runtime_entrypoint") == "assertion_check"
    and isinstance(obj.get("entrypoint_refs"), dict)
)
target["entrypoint_refs"]["assertion"] = "__spoofed_entrypoint_ref__"
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-entrypoint-refs.json" \
  2> "$TMP_DIR/compile-bad-lowered-entrypoint-refs.err"; then
  echo "expected artifact report validator to reject spoofed lowered IR entrypoint refs" >&2
  exit 1
fi
grep -q 'entrypoint ref' \
  "$TMP_DIR/compile-bad-lowered-entrypoint-refs.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-entrypoint-refs.json" \
  2> "$TMP_DIR/compile-bad-lowered-entrypoint-refs-rust.err"; then
  echo "expected whip verify-report to reject spoofed lowered IR entrypoint refs" >&2
  exit 1
fi
grep -q 'entrypoint_ref_mismatch' \
  "$TMP_DIR/compile-bad-lowered-entrypoint-refs-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-entrypoint-extra.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
target = next(
    obj for obj in lowered["core_objects"]
    if obj.get("runtime_entrypoint") == "assertion_check"
    and isinstance(obj.get("entrypoint_refs"), dict)
)
target["entrypoint_refs"]["unexpected_semantic_ref"] = "stale"
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-entrypoint-extra.json" \
  2> "$TMP_DIR/compile-bad-lowered-entrypoint-extra.err"; then
  echo "expected artifact report validator to reject extra lowered IR entrypoint refs" >&2
  exit 1
fi
grep -q 'Additional properties are not allowed' \
  "$TMP_DIR/compile-bad-lowered-entrypoint-extra.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-entrypoint-extra.json" \
  > "$TMP_DIR/compile-bad-lowered-entrypoint-extra.maude" \
  2> "$TMP_DIR/compile-bad-lowered-entrypoint-extra.bridge.err"; then
  echo "expected lowered IR bridge to reject extra lowered IR entrypoint refs" >&2
  exit 1
fi
grep -q 'Additional properties are not allowed' \
  "$TMP_DIR/compile-bad-lowered-entrypoint-extra.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-entrypoint-extra.json" \
  2> "$TMP_DIR/compile-bad-lowered-entrypoint-extra-rust.err"; then
  echo "expected whip verify-report to reject extra lowered IR entrypoint refs" >&2
  exit 1
fi
grep -q 'entrypoint_ref_unknown' \
  "$TMP_DIR/compile-bad-lowered-entrypoint-extra-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-source-span.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
target = next(
    obj for obj in lowered["core_objects"]
    if isinstance(obj.get("source_span"), dict)
)
target["source_span"]["start"] = -1
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-source-span.json" \
  2> "$TMP_DIR/compile-bad-lowered-source-span.err"; then
  echo "expected artifact report validator to reject invalid lowered IR source span" >&2
  exit 1
fi
grep -q 'less than the minimum' \
  "$TMP_DIR/compile-bad-lowered-source-span.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-source-span.json" \
  > "$TMP_DIR/compile-bad-lowered-source-span.maude" \
  2> "$TMP_DIR/compile-bad-lowered-source-span.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR source span" >&2
  exit 1
fi
grep -q 'less than the minimum' \
  "$TMP_DIR/compile-bad-lowered-source-span.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-source-span.json" \
  2> "$TMP_DIR/compile-bad-lowered-source-span-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR source span" >&2
  exit 1
fi
grep -q 'lowered_ir.core_object.source_span_invalid' \
  "$TMP_DIR/compile-bad-lowered-source-span-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
for fact in lowered["derived_facts"]:
    refs = fact.get("input_refs")
    if isinstance(refs, list) and refs:
        refs.append(refs[0])
        break
else:
    raise SystemExit("lowered IR report did not contain a derived fact input ref")
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.json" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.err"; then
  echo "expected artifact report validator to reject duplicate lowered IR derived fact input refs" >&2
  exit 1
fi
grep -Eq 'non-unique|duplicate input_refs|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.json" \
  > "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.maude" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.bridge.err"; then
  echo "expected lowered IR bridge to reject duplicate lowered IR derived fact input refs" >&2
  exit 1
fi
grep -Eq 'non-unique|duplicate input_refs|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs.json" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs-rust.err"; then
  echo "expected whip verify-report to reject duplicate lowered IR derived fact input refs" >&2
  exit 1
fi
grep -q 'lowered_ir.derived_fact.input_refs_invalid' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-input-refs-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
fact = lowered["derived_facts"][0]
fact["owner_subsystem"] = ""
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.json" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.err"; then
  echo "expected artifact report validator to reject invalid lowered IR derived fact metadata" >&2
  exit 1
fi
grep -Eq 'should be non-empty|is too short|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.json" \
  > "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.maude" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR derived fact metadata" >&2
  exit 1
fi
grep -Eq 'should be non-empty|is too short|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-derived-fact-metadata.json" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-metadata-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR derived fact metadata" >&2
  exit 1
fi
grep -q 'lowered_ir.derived_fact.metadata_invalid' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-metadata-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-derived-fact-span.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
fact = lowered["derived_facts"][0]
fact["diagnostic_span"]["start"] = -1
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-derived-fact-span.json" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-span.err"; then
  echo "expected artifact report validator to reject invalid lowered IR derived fact span" >&2
  exit 1
fi
grep -Eq 'less than the minimum|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-span.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-derived-fact-span.json" \
  > "$TMP_DIR/compile-bad-lowered-derived-fact-span.maude" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-span.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR derived fact span" >&2
  exit 1
fi
grep -Eq 'less than the minimum|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-span.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-derived-fact-span.json" \
  2> "$TMP_DIR/compile-bad-lowered-derived-fact-span-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR derived fact span" >&2
  exit 1
fi
grep -q 'lowered_ir.derived_fact.diagnostic_span_invalid' \
  "$TMP_DIR/compile-bad-lowered-derived-fact-span-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-diagnostic-span.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
lowered["diagnostics"] = [
    {
        "code": "lowered_ir.test.warning",
        "severity": "warning",
        "refs": {},
        "source_span": {
            "path": None,
            "start": -1,
            "end": 0,
            "construct": None,
        },
        "message": "malformed diagnostic span fixture",
    }
]
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-diagnostic-span.json" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostic-span.err"; then
  echo "expected artifact report validator to reject invalid lowered IR diagnostic span" >&2
  exit 1
fi
grep -Eq 'less than the minimum|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-diagnostic-span.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-diagnostic-span.json" \
  > "$TMP_DIR/compile-bad-lowered-diagnostic-span.maude" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostic-span.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR diagnostic span" >&2
  exit 1
fi
grep -Eq 'less than the minimum|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-diagnostic-span.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-diagnostic-span.json" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostic-span-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR diagnostic span" >&2
  exit 1
fi
grep -q 'lowered_ir.diagnostic.source_span_invalid' \
  "$TMP_DIR/compile-bad-lowered-diagnostic-span-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
lowered = report["lowered_ir_report"]
lowered["diagnostics"] = [
    {
        "code": "lowered_ir.test.warning",
        "severity": "not-a-severity",
        "refs": {},
        "source_span": {
            "path": None,
            "start": 0,
            "end": 0,
            "construct": None,
        },
        "message": "malformed diagnostic metadata fixture",
    }
]
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.json" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.err"; then
  echo "expected artifact report validator to reject invalid lowered IR diagnostic metadata" >&2
  exit 1
fi
grep -Eq 'not one of|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.json" \
  > "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.maude" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR diagnostic metadata" >&2
  exit 1
fi
grep -Eq 'not one of|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-diagnostic-metadata.json" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostic-metadata-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR diagnostic metadata" >&2
  exit 1
fi
grep -q 'lowered_ir.diagnostic.metadata_invalid' \
  "$TMP_DIR/compile-bad-lowered-diagnostic-metadata-rust.err"

python3 - "$TMP_DIR/compile.json" "$TMP_DIR/compile-bad-lowered-diagnostics-type.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["lowered_ir_report"]["diagnostics"] = "not-an-array"
with open(sys.argv[2], "w") as handle:
    json.dump(report, handle)
PY
if validate_artifact_reports \
  "$TMP_DIR/compile-bad-lowered-diagnostics-type.json" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostics-type.err"; then
  echo "expected artifact report validator to reject invalid lowered IR diagnostics collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-diagnostics-type.err"
if lowered_ir_to_maude \
  "$TMP_DIR/compile-bad-lowered-diagnostics-type.json" \
  > "$TMP_DIR/compile-bad-lowered-diagnostics-type.maude" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostics-type.bridge.err"; then
  echo "expected lowered IR bridge to reject invalid lowered IR diagnostics collection" >&2
  exit 1
fi
grep -Eq 'is not of type .array.|not valid under any' \
  "$TMP_DIR/compile-bad-lowered-diagnostics-type.bridge.err"
if cargo run --quiet -p whipplescript -- verify-report \
  "$TMP_DIR/compile-bad-lowered-diagnostics-type.json" \
  2> "$TMP_DIR/compile-bad-lowered-diagnostics-type-rust.err"; then
  echo "expected whip verify-report to reject invalid lowered IR diagnostics collection" >&2
  exit 1
fi
grep -q 'lowered_ir_report.diagnostics must be an array' \
  "$TMP_DIR/compile-bad-lowered-diagnostics-type-rust.err"
