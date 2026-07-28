#!/usr/bin/env python3
"""Lower a verified/check/compile construct_graph artifact into Maude obligations."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from artifact_admission import (
    catalog_lowerings,
    is_sha256_digest,
    load_platform_construct_catalog,
    validate_contract_registry_shape,
    validate_empty_diagnostics,
    validate_package_contract_spine,
    validate_package_contract_platform,
)

try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError, ValidationError
except Exception as exc:
    raise SystemExit(
        "python jsonschema package is required; run under `nix develop` or "
        f"install `requirements-dev.txt`: {exc}"
    )


PORT_KIND = {
    "Resource": "resourceKind",
    "Projection": "projectionKind",
    "Event": "eventKind",
    "SignalSource": "eventSourceKind",
    "Value": "valueKind",
    "EffectHandle": "effectHandleKind",
    "TerminalOutput": "terminalOutputKind",
    "Capability": "capabilityKind",
    "Operation": "operationKind",
}

PHASE = {
    "compile": "compilePhase",
    "runtime": "runtimePhase",
    "both": "bothPhase",
}

CARDINALITY = {
    "exactly-one": "exactlyOne",
    "optional-one": "optionalOne",
    "many": "many",
    "named-many": "namedMany",
}

ADEQUACY_FACTS = [
    (
        "sourceAndLockDeterministic",
        "source_lock_deterministic",
        [
            "root:graph_id",
            "root:source_digest",
            "root:package_lock_digest",
        ],
    ),
    (
        "registryClosed",
        "registry_closed",
        [
            "root:graph_id",
            "root:platform_version",
            "root:package_lock_digest",
            "root:package_contract_digest",
        ],
    ),
    (
        "checkerFactsAccounted",
        "checker_facts_accounted",
        [
            "root:graph_id",
            "validator_scope:construct_graph_validator",
            "validator_predicate:graph.accepted",
        ],
    ),
    (
        "checkerFactsConsistent",
        "checker_facts_consistent",
        [
            "root:graph_id",
            "diagnostics:error_count:0",
            "validator_scope:construct_graph_validator",
        ],
    ),
    (
        "namespaceStable",
        "namespace_stable",
        ["root:graph_id", "namespace:nodes_ports_edges_dependencies"],
    ),
    (
        "constructIdentityStable",
        "construct_identity_stable",
        [
            "root:graph_id",
            "root:platform_version",
            "root:package_contract_digest",
        ],
    ),
    (
        "authorityScoped",
        "authority_scoped",
        [
            "root:graph_id",
            "root:package_contract_digest",
            "authority:package_declared_capabilities_only",
        ],
    ),
    (
        "phaseSeparated",
        "phase_separated",
        ["root:graph_id", "phase_model:compile_runtime_both"],
    ),
    (
        "cardinalityChecked",
        "cardinality_checked",
        [
            "root:graph_id",
            "cardinality_model:exactly-one_optional-one_many_named-many",
        ],
    ),
    (
        "versionReplayPinned",
        "version_replay_pinned",
        [
            "root:graph_id",
            "root:package_lock_digest",
            "root:package_contract_digest",
        ],
    ),
    (
        "diagnosticsComplete",
        "diagnostics_complete",
        ["root:graph_id", "diagnostics:error_count:0"],
    ),
    (
        "loweringBoundaryDeclared",
        "lowering_boundary_declared",
        [
            "root:graph_id",
            "root:platform_version",
            "lowering_boundary:platform_catalog",
        ],
    ),
    (
        "lifecycleBoundaryDeclared",
        "lifecycle_boundary_declared",
        [
            "root:graph_id",
            "root:platform_version",
            "lifecycle_boundary:lowering_class_profiles",
        ],
    ),
]

RUNTIME_ENTRYPOINT_BY_CORE_OBJECT_KIND = {
    "fact": "fact_record",
    "event": "event_record",
    "signal_source": "signal_source_template",
    "schedule": "schedule_template",
    "effect": "effect_graph_template",
    "rule": "rule_template",
    "dependency": "effect_dependency_template",
    "projection": "event_projection",
    "assertion": "assertion_check",
    "diagnostic": "diagnostic_record",
}

CURRENT_SUPPORTED_CORE_OBJECT_KINDS = {
    "fact",
    "event",
    "effect",
    "signal_source",
    "schedule",
    "rule",
    "dependency",
    "projection",
    "assertion",
    "diagnostic",
}

CURRENT_SUPPORTED_RUNTIME_ENTRYPOINTS = {
    "fact_record",
    "event_record",
    "effect_graph_template",
    "signal_source_template",
    "schedule_template",
    "rule_template",
    "effect_dependency_template",
    "event_projection",
    "assertion_check",
    "diagnostic_record",
}

class SymbolTable:
    def __init__(self) -> None:
        self.by_sort: dict[str, dict[str, str]] = {}

    def symbol(self, sort: str, prefix: str, value: str) -> str:
        values = self.by_sort.setdefault(sort, {})
        if value not in values:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
            values[value] = f"{prefix}{digest}"
        return values[value]

    def emit_ops(self) -> list[str]:
        lines: list[str] = []
        for sort, values in sorted(self.by_sort.items()):
            symbols = sorted(values.values())
            if symbols:
                lines.append(f"  ops {' '.join(symbols)} : -> {sort} .")
        return lines


def validate_json_schema(root: Path, schema_name: str, value: Any, label: str) -> None:
    schema_path = root / "spec" / "report-schemas" / schema_name
    schema = json.loads(schema_path.read_text())
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)
    except (SchemaError, ValidationError) as exc:
        raise SystemExit(
            f"{label} failed schema validation against {schema_name}: {exc.message}"
        ) from exc


def stable_hash_hex(value: str) -> str:
    # Mirrors the Rust stable_hash: SHA-256 truncated to 128 bits (the
    # FNV-collision hardening swap). Extend every mirror together.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def is_stable_digest(value: str) -> bool:
    return len(value) == 32 and all(ch in "0123456789abcdef" for ch in value)


def required_string(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str):
        raise SystemExit(f"{label}.{field} must be a string")
    return result


def validate_report_entry_identity(
    root: Path,
    verifier_catalog: dict[str, Any],
    entry: dict[str, Any],
    graph: dict[str, Any],
    label: str,
) -> None:
    snapshot = required_string(entry, "snapshot", label)
    ir_hash = required_string(entry, "ir_hash", label)
    source_hash = required_string(entry, "source_hash", label)
    if not is_stable_digest(ir_hash):
        raise SystemExit(f"{label}.ir_hash must be a 32-character lowercase hex digest")
    if not is_stable_digest(source_hash):
        raise SystemExit(f"{label}.source_hash must be a 32-character lowercase hex digest")
    expected_ir_hash = stable_hash_hex(snapshot)
    if ir_hash != expected_ir_hash:
        raise SystemExit(
            f"{label}.ir_hash must match embedded snapshot hash: "
            f"got {ir_hash!r}, expected {expected_ir_hash!r}"
        )

    contract_registry = entry.get("contract_registry")
    if not isinstance(contract_registry, dict):
        raise SystemExit(f"{label}.contract_registry must be an object")
    validate_contract_registry_shape(contract_registry, f"{label}.contract_registry")
    validate_json_schema(
        root,
        "package_contract_v0.schema.json",
        entry.get("package_contract"),
        "package contract",
    )
    package_contract = entry.get("package_contract")
    if not isinstance(package_contract, dict):
        raise SystemExit(f"{label}.package_contract must be an object")
    embedded_registry = validate_package_contract_spine(
        package_contract,
        f"{label}.package_contract",
    )
    validate_package_contract_platform(
        root,
        verifier_catalog,
        package_contract,
        f"{label}.package_contract",
    )
    if package_contract.get("contract_registry") != contract_registry:
        raise SystemExit(f"{label}.package_contract.contract_registry must match contract_registry")
    validate_empty_diagnostics(package_contract, "diagnostics", f"{label}.package_contract")
    validate_empty_diagnostics(
        embedded_registry,
        "diagnostics",
        f"{label}.package_contract.contract_registry",
    )
    validate_empty_diagnostics(contract_registry, "diagnostics", f"{label}.contract_registry")
    package_contract_digest = package_contract.get("package_contract_digest")
    if not isinstance(package_contract_digest, str) or not is_sha256_digest(package_contract_digest):
        raise SystemExit(
            f"{label}.package_contract.package_contract_digest must be a "
            "64-character lowercase hex digest"
        )
    digest_body = dict(package_contract)
    digest_body.pop("package_contract_digest", None)
    expected_package_contract_digest = hashlib.sha256(
        canonical_json(digest_body).encode("utf-8")
    ).hexdigest()
    if package_contract_digest != expected_package_contract_digest:
        raise SystemExit(
            f"{label}.package_contract.package_contract_digest does not match "
            "the embedded package contract"
        )

    source_digest = graph.get("source_digest")
    if not isinstance(source_digest, str) or not is_sha256_digest(source_digest):
        raise SystemExit(
            f"{label} construct_graph.source_digest must be a 64-character lowercase hex digest"
        )
    graph_id = graph.get("graph_id")
    expected_graph_id = f"construct_graph:{source_digest}"
    if graph_id != expected_graph_id:
        raise SystemExit(
            f"{label} construct_graph.graph_id must be {expected_graph_id!r}, "
            f"got {graph_id!r}"
        )
    if graph.get("package_contract_digest") != package_contract_digest:
        raise SystemExit(
            f"{label} construct_graph.package_contract_digest does not match "
            "package_contract.package_contract_digest"
        )
    if graph.get("package_lock_digest") != package_contract.get("package_lock_digest"):
        raise SystemExit(
            f"{label} construct_graph.package_lock_digest does not match "
            "package_contract.package_lock_digest"
        )


def load_report_entry(
    root: Path,
    report_path: Path,
    entry_index: int | None,
) -> tuple[dict[str, Any], str]:
    report = json.loads(report_path.read_text())
    if isinstance(report, list):
        validate_json_schema(root, "check_report_v0.schema.json", report, "check report")
        if not report:
            raise SystemExit(f"{report_path} is not a non-empty check report array")
        if entry_index is None:
            if len(report) != 1:
                raise SystemExit(
                    f"{report_path} contains {len(report)} check report entries; "
                    "pass --entry-index to select the artifact to lower"
                )
            selected_index = 0
        else:
            selected_index = entry_index
            if selected_index < 0 or selected_index >= len(report):
                raise SystemExit(
                    f"--entry-index {selected_index} is out of range for "
                    f"{report_path} with {len(report)} entr"
                    f"{'y' if len(report) == 1 else 'ies'}"
                )
        entry = report[selected_index]
        label = f"{report_path} entry {selected_index}"
        if not isinstance(entry, dict):
            raise SystemExit(f"{label} is not an object")
        if entry.get("status") != "ok":
            raise SystemExit(f"{label} was not ok")
    elif isinstance(report, dict) and report.get("schema") == "whipplescript.verified_artifacts.v0":
        validate_json_schema(
            root,
            "verified_artifacts_v0.schema.json",
            report,
            "verified artifact bundle",
        )
        if report.get("status") != "ok":
            raise SystemExit(f"{report_path} verified artifact bundle was not ok")
        entries = report.get("entries")
        if not isinstance(entries, list) or not entries:
            raise SystemExit(f"{report_path} is not a non-empty verified artifact bundle")
        if entry_index is None:
            if len(entries) != 1:
                raise SystemExit(
                    f"{report_path} contains {len(entries)} verified artifact entries; "
                    "pass --entry-index to select the artifact to lower"
                )
            selected_index = 0
        else:
            selected_index = entry_index
            if selected_index < 0 or selected_index >= len(entries):
                raise SystemExit(
                    f"--entry-index {selected_index} is out of range for "
                    f"{report_path} with {len(entries)} entr"
                    f"{'y' if len(entries) == 1 else 'ies'}"
                )
        entry = entries[selected_index]
        label = f"{report_path} verified artifact entry {selected_index}"
        if not isinstance(entry, dict):
            raise SystemExit(f"{label} is not an object")
    elif isinstance(report, dict):
        validate_json_schema(
            root,
            "compile_report_v0.schema.json",
            report,
            "compile report",
        )
        entry = report
        label = f"{report_path} compile report"
        if entry.get("status") == "error":
            raise SystemExit(f"{label} was not ok")
    else:
        raise SystemExit(
            f"{report_path} is not a check report array, compile report object, "
            "or verified artifact bundle"
        )
    if not isinstance(entry, dict):
        raise SystemExit(f"{label} is not an object")
    return entry, label


def load_construct_graph(
    root: Path,
    verifier_catalog: dict[str, Any],
    report_path: Path,
    entry_index: int | None,
) -> dict[str, Any]:
    entry, label = load_report_entry(root, report_path, entry_index)
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        raise SystemExit(f"{label} has no construct_graph")
    validate_report_entry_identity(root, verifier_catalog, entry, graph, label)
    validate_json_schema(
        root,
        "construct_graph_v0.schema.json",
        graph,
        "construct graph",
    )
    diagnostics = graph.get("diagnostics", [])
    errors = [diag for diag in diagnostics if diag.get("severity") == "error"]
    if errors:
        codes = ", ".join(str(diag.get("code", "unknown")) for diag in errors)
        raise SystemExit(f"construct graph has validator errors: {codes}")
    validate_construct_graph_trace(graph, verifier_catalog)
    return graph


def edge_ref(edge: dict[str, Any]) -> str:
    required_port_id = edge.get("required_port_id", "unknown")
    provided_port_id = edge.get("provided_port_id", "unknown")
    return f"{required_port_id}->{provided_port_id}"


def cardinality_fact_refs(port: dict[str, Any], edges: list[dict[str, Any]]) -> list[str]:
    port_id = port.get("port_id", "unknown")
    cardinality = port.get("cardinality", "unknown")
    refs = [port_id] if isinstance(port_id, str) and port_id else []
    for edge in edges:
        ref = edge_ref(edge)
        refs.append(ref)
        if cardinality in {"many", "named-many"}:
            order_index = edge.get("order_index")
            if isinstance(order_index, int):
                refs.append(f"{ref}#order_index:{order_index}")
        if cardinality == "named-many":
            resource_key = edge.get("resource_key")
            if isinstance(resource_key, str):
                refs.append(f"{ref}#resource_key:{resource_key}")
    return refs


def graph_root_field_ref(graph: dict[str, Any], field: str) -> str:
    value = graph.get(field)
    if not isinstance(value, str) or not value:
        value = "unknown"
    return f"construct_graph.root.{field}:{value}"


def graph_adequacy_refs(graph: dict[str, Any], ref_specs: list[str]) -> list[str]:
    refs: list[str] = []
    for ref_spec in ref_specs:
        if ref_spec.startswith("root:"):
            refs.append(graph_root_field_ref(graph, ref_spec.removeprefix("root:")))
        else:
            refs.append(f"construct_graph.{ref_spec}")
    return refs


def validate_construct_graph_cardinality(graph: dict[str, Any]) -> None:
    ports = graph.get("ports", [])
    edges = graph.get("edges", [])
    if not isinstance(ports, list) or not isinstance(edges, list):
        raise SystemExit("construct graph ports and edges must be arrays")
    edges_by_required: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        required_port_id = edge.get("required_port_id")
        if isinstance(required_port_id, str) and required_port_id:
            edges_by_required.setdefault(required_port_id, []).append(edge)

    for port in ports:
        if not isinstance(port, dict) or port.get("direction") != "required":
            continue
        port_id = port.get("port_id")
        if not isinstance(port_id, str) or not port_id:
            continue
        cardinality = port.get("cardinality", "exactly-one")
        port_edges = edges_by_required.get(port_id, [])
        if cardinality == "exactly-one":
            if len(port_edges) != 1:
                raise SystemExit(
                    f"construct graph required port {port_id!r} expects exactly "
                    f"one provider but resolved {len(port_edges)}"
                )
            validate_scalar_cardinality_edges(port_id, port_edges)
        elif cardinality == "optional-one":
            if len(port_edges) > 1:
                raise SystemExit(
                    f"construct graph required port {port_id!r} expects at most "
                    f"one provider but resolved {len(port_edges)}"
                )
            validate_scalar_cardinality_edges(port_id, port_edges)
        elif cardinality == "many":
            validate_aggregate_cardinality_edges(port_id, port_edges, False)
        elif cardinality == "named-many":
            validate_aggregate_cardinality_edges(port_id, port_edges, True)
        else:
            raise SystemExit(
                f"construct graph required port {port_id!r} has unsupported "
                f"cardinality {cardinality!r}"
            )


def validate_construct_graph_node_outputs(graph: dict[str, Any]) -> None:
    nodes = graph.get("nodes", [])
    if not isinstance(nodes, list):
        raise SystemExit("construct graph nodes must be an array")
    known_entrypoints = set(RUNTIME_ENTRYPOINT_BY_CORE_OBJECT_KIND.values())
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = construct_graph_string(node, "node_id") or "unknown"
        object_kinds = string_array_refs(node, "allowed_core_object_kinds")
        runtime_entrypoints = string_array_refs(node, "allowed_runtime_entrypoints")
        runtime_entrypoint_set = set(runtime_entrypoints)
        expected_entrypoints: set[str] = set()

        for object_kind in object_kinds:
            expected_entrypoint = RUNTIME_ENTRYPOINT_BY_CORE_OBJECT_KIND.get(object_kind)
            if expected_entrypoint is None:
                raise SystemExit(
                    f"construct graph node {node_id!r} allows unknown core "
                    f"object kind {object_kind!r}"
                )
            expected_entrypoints.add(expected_entrypoint)
            if object_kind not in CURRENT_SUPPORTED_CORE_OBJECT_KINDS:
                raise SystemExit(
                    f"construct graph node {node_id!r} allows known core "
                    f"object kind {object_kind!r} before the current executable "
                    "lowering/runtime handoff slice admits it"
                )

        for runtime_entrypoint in runtime_entrypoints:
            if runtime_entrypoint not in known_entrypoints:
                raise SystemExit(
                    f"construct graph node {node_id!r} allows unknown runtime "
                    f"entrypoint {runtime_entrypoint!r}"
                )
            if runtime_entrypoint not in CURRENT_SUPPORTED_RUNTIME_ENTRYPOINTS:
                raise SystemExit(
                    f"construct graph node {node_id!r} allows known runtime "
                    f"entrypoint {runtime_entrypoint!r} before the current "
                    "executable lowering/runtime handoff slice admits it"
                )
            if object_kinds and runtime_entrypoint not in expected_entrypoints:
                raise SystemExit(
                    f"construct graph node {node_id!r} allows runtime entrypoint "
                    f"{runtime_entrypoint!r} that is not produced by its allowed "
                    "core object kinds"
                )

        for expected_entrypoint in sorted(expected_entrypoints):
            if expected_entrypoint not in runtime_entrypoint_set:
                raise SystemExit(
                    f"construct graph node {node_id!r} allows a core object kind "
                    f"whose runtime entrypoint {expected_entrypoint!r} is missing"
                )


def validate_construct_graph_lifecycle_profiles(
    graph: dict[str, Any],
    verifier_catalog: dict[str, Any],
) -> None:
    nodes = graph.get("nodes", [])
    if not isinstance(nodes, list):
        raise SystemExit("construct graph nodes must be an array")
    lowerings = catalog_lowerings(verifier_catalog)
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = construct_graph_string(node, "node_id") or "unknown"
        lowering_class = construct_graph_string(node, "lowering_class")
        lifecycle_profile = construct_graph_string(node, "lifecycle_profile")
        if lowering_class is None:
            raise SystemExit(
                f"construct graph node {node_id!r} is missing lowering_class"
            )
        if lifecycle_profile is None:
            raise SystemExit(
                f"construct graph node {node_id!r} is missing lifecycle_profile"
            )
        lowering = lowerings.get(lowering_class)
        if not isinstance(lowering, dict):
            raise SystemExit(
                f"construct graph node {node_id!r} uses unsupported lowering "
                f"class {lowering_class!r}"
            )
        compatible_families = set(string_array_refs(lowering, "compatible_families"))
        construct_family = construct_graph_string(node, "construct_family")
        if construct_family not in compatible_families:
            expected = ", ".join(sorted(compatible_families))
            raise SystemExit(
                f"construct graph node {node_id!r} lowering class "
                f"{lowering_class!r} is incompatible with construct family "
                f"{construct_family!r}; expected one of {expected}"
            )
        allowed_profiles = set(string_array_refs(lowering, "lifecycle_profiles"))
        if lifecycle_profile not in allowed_profiles:
            expected = ", ".join(sorted(allowed_profiles))
            raise SystemExit(
                f"construct graph node {node_id!r} lowering class "
                f"{lowering_class!r} requires lifecycle profile {expected}, "
                f"got {lifecycle_profile!r}"
            )


def validate_scalar_cardinality_edges(port_id: str, edges: list[dict[str, Any]]) -> None:
    for edge in edges:
        if edge.get("order_index") is not None or edge.get("resource_key") is not None:
            raise SystemExit(
                f"construct graph scalar required port {port_id!r} edge "
                f"{edge_ref(edge)!r} carries aggregate metadata"
            )


def validate_aggregate_cardinality_edges(
    port_id: str,
    edges: list[dict[str, Any]],
    require_resource_key: bool,
) -> None:
    order_indices: set[int] = set()
    resource_keys: set[str] = set()
    for edge in edges:
        ref = edge_ref(edge)
        order_index = edge.get("order_index")
        if not isinstance(order_index, int):
            raise SystemExit(
                f"construct graph aggregate required port {port_id!r} edge "
                f"{ref!r} is missing order_index"
            )
        if order_index in order_indices:
            raise SystemExit(
                f"construct graph aggregate required port {port_id!r} uses "
                f"order_index {order_index} more than once"
            )
        order_indices.add(order_index)

        resource_key = edge.get("resource_key")
        if require_resource_key:
            if not isinstance(resource_key, str) or not resource_key:
                raise SystemExit(
                    f"construct graph named-many required port {port_id!r} "
                    f"edge {ref!r} is missing resource_key"
                )
            if resource_key in resource_keys:
                raise SystemExit(
                    f"construct graph named-many required port {port_id!r} "
                    f"uses resource_key {resource_key!r} more than once"
                )
            resource_keys.add(resource_key)
        elif resource_key is not None:
            raise SystemExit(
                f"construct graph many required port {port_id!r} edge "
                f"{ref!r} unexpectedly carries resource_key"
            )

    expected = set(range(len(edges)))
    if order_indices != expected:
        raise SystemExit(
            f"construct graph aggregate required port {port_id!r} order_index "
            "values must be contiguous from zero"
        )


def construct_graph_string(value: dict[str, Any], key: str) -> str | None:
    item = value.get(key)
    if isinstance(item, str) and item:
        return item
    return None


def construct_graph_phase_compatible(
    required: str | None,
    provided: str | None,
) -> bool:
    if required == "both" and provided == "both":
        return True
    if required == "both":
        return False
    if provided == "both":
        return required in {"compile", "runtime"}
    if required is not None and provided is not None:
        return required == provided
    return False


def construct_graph_interface_phase_matches_port(
    interface_phase: str | None,
    port_phase: str | None,
) -> bool:
    if interface_phase in {"compile/runtime", "both"}:
        return port_phase in {"compile", "runtime", "both"}
    if interface_phase == "compile":
        return port_phase in {"compile", "both"}
    if interface_phase == "runtime":
        return port_phase in {"runtime", "both"}
    return False


def construct_graph_port_satisfies_interface(
    port: dict[str, Any],
    interface: dict[str, Any],
) -> bool:
    kind = construct_graph_string(interface, "kind")
    if kind is None or construct_graph_string(port, "kind") != kind:
        return False
    name = construct_graph_string(interface, "name")
    if name is not None and port.get("type") != name and port.get("resource_identity") != name:
        return False
    type_ref = construct_graph_string(interface, "type")
    if type_ref is not None and port.get("type") != type_ref:
        return False
    if not construct_graph_interface_phase_matches_port(
        construct_graph_string(interface, "phase"),
        construct_graph_string(port, "phase"),
    ):
        return False
    return interface.get("cardinality") == port.get("cardinality")


def validate_construct_graph_node_interfaces(
    node: dict[str, Any],
    ports_by_id: dict[str, dict[str, Any]],
    verifier_catalog: dict[str, Any],
) -> None:
    node_id = construct_graph_string(node, "node_id") or "unknown"
    for interface_key, port_key, direction in [
        ("declared_required_interfaces", "required_ports", "required"),
        ("declared_provided_interfaces", "produced_ports", "provided"),
    ]:
        port_ids = string_array_refs(node, port_key)
        ports = [ports_by_id[port_id] for port_id in port_ids if port_id in ports_by_id]
        for interface in node.get(interface_key, []):
            if not isinstance(interface, dict):
                raise SystemExit(
                    f"construct graph node {node_id!r} has a non-object {direction} interface"
                )
            if not any(
                construct_graph_port_satisfies_interface(port, interface)
                for port in ports
            ):
                kind = construct_graph_string(interface, "kind") or "unknown"
                raise SystemExit(
                    f"construct graph node {node_id!r} declares {direction} "
                    f"interface {kind!r} but no {direction} port satisfies it"
                )
    validate_construct_graph_node_lowering_interfaces(
        node,
        node_id,
        verifier_catalog,
    )


def validate_construct_graph_node_lowering_interfaces(
    node: dict[str, Any],
    node_id: str,
    verifier_catalog: dict[str, Any],
) -> None:
    lowering_class = construct_graph_string(node, "lowering_class")
    if lowering_class is None:
        return
    lowering = catalog_lowerings(verifier_catalog).get(lowering_class)
    if not isinstance(lowering, dict):
        return
    for kind in string_array_refs(lowering, "required_interfaces"):
        if not construct_graph_node_declares_interface(
            node,
            "declared_required_interfaces",
            kind,
        ):
            raise SystemExit(
                f"construct graph node {node_id!r} uses {lowering_class!r} "
                f"lowering but declares no required {kind!r} interface"
            )
    for kind in string_array_refs(lowering, "provided_interfaces"):
        if not construct_graph_node_declares_interface(
            node,
            "declared_provided_interfaces",
            kind,
        ):
            raise SystemExit(
                f"construct graph node {node_id!r} uses {lowering_class!r} "
                f"lowering but declares no provided {kind!r} interface"
            )


def construct_graph_node_declares_interface(
    node: dict[str, Any],
    key: str,
    kind: str,
) -> bool:
    return any(
        isinstance(interface, dict) and interface.get("kind") == kind
        for interface in node.get(key, [])
    )


def validate_construct_graph_inventory(
    graph: dict[str, Any],
    verifier_catalog: dict[str, Any],
) -> None:
    nodes = graph.get("nodes", [])
    ports = graph.get("ports", [])
    edges = graph.get("edges", [])
    dependencies = graph.get("effect_dependencies", [])
    if not all(isinstance(collection, list) for collection in [nodes, ports, edges, dependencies]):
        raise SystemExit("construct graph inventory collections must be arrays")

    nodes_by_id = {
        node.get("node_id"): node
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("node_id"), str)
    }
    ports_by_id = {
        port.get("port_id"): port
        for port in ports
        if isinstance(port, dict) and isinstance(port.get("port_id"), str)
    }

    for port in ports:
        if not isinstance(port, dict):
            raise SystemExit("construct graph ports entries must be objects")
        port_id = construct_graph_string(port, "port_id")
        owner_node_id = construct_graph_string(port, "owner_node_id")
        direction = construct_graph_string(port, "direction")
        if port_id is None:
            raise SystemExit("construct graph port is missing port_id")
        if owner_node_id is None or owner_node_id not in nodes_by_id:
            raise SystemExit(
                f"construct graph port {port_id!r} references unknown owner node {owner_node_id!r}"
            )
        if direction not in {"required", "produced"}:
            raise SystemExit(
                f"construct graph port {port_id!r} has unsupported direction {direction!r}"
            )

    for node in nodes:
        if not isinstance(node, dict):
            raise SystemExit("construct graph nodes entries must be objects")
        node_id = construct_graph_string(node, "node_id")
        if node_id is None:
            raise SystemExit("construct graph node is missing node_id")
        for field, expected_direction in [
            ("required_ports", "required"),
            ("produced_ports", "produced"),
        ]:
            for port_id in string_array_refs(node, field):
                port = ports_by_id.get(port_id)
                if port is None:
                    raise SystemExit(
                        f"construct graph node {node_id!r} references missing port {port_id!r}"
                    )
                if construct_graph_string(port, "owner_node_id") != node_id:
                    raise SystemExit(
                        f"construct graph node {node_id!r} lists port {port_id!r} "
                        "owned by another node"
                    )
                if construct_graph_string(port, "direction") != expected_direction:
                    raise SystemExit(
                        f"construct graph node {node_id!r} lists port {port_id!r} "
                        f"as {expected_direction!r} but the port declares another direction"
                    )
        validate_construct_graph_node_interfaces(node, ports_by_id, verifier_catalog)

    for edge in edges:
        if not isinstance(edge, dict):
            raise SystemExit("construct graph edges entries must be objects")
        ref = edge_ref(edge)
        required_port_id = construct_graph_string(edge, "required_port_id")
        provided_port_id = construct_graph_string(edge, "provided_port_id")
        provider_node_id = construct_graph_string(edge, "provider_node_id")
        if provider_node_id is None or provider_node_id not in nodes_by_id:
            raise SystemExit(
                f"construct graph edge {ref!r} references missing provider node {provider_node_id!r}"
            )
        required_port = ports_by_id.get(required_port_id)
        provided_port = ports_by_id.get(provided_port_id)
        if required_port is None:
            raise SystemExit(
                f"construct graph edge {ref!r} references missing required port {required_port_id!r}"
            )
        if provided_port is None:
            raise SystemExit(
                f"construct graph edge {ref!r} references missing provided port {provided_port_id!r}"
            )
        if construct_graph_string(required_port, "direction") != "required":
            raise SystemExit(
                f"construct graph edge {ref!r} starts from a non-required port"
            )
        if construct_graph_string(provided_port, "direction") != "produced":
            raise SystemExit(
                f"construct graph edge {ref!r} ends at a non-produced port"
            )
        if construct_graph_string(provided_port, "owner_node_id") != provider_node_id:
            raise SystemExit(
                f"construct graph edge {ref!r} provider node does not own provided port {provided_port_id!r}"
            )
        for field in ["kind", "type", "contract_version"]:
            if required_port.get(field) != provided_port.get(field):
                raise SystemExit(
                    f"construct graph edge {ref!r} has incompatible port {field!r}"
                )
        if not construct_graph_phase_compatible(
            construct_graph_string(required_port, "phase"),
            construct_graph_string(provided_port, "phase"),
        ):
            raise SystemExit(
                f"construct graph edge {ref!r} has incompatible port phases"
            )
        if required_port.get("resource_identity") != provided_port.get("resource_identity"):
            raise SystemExit(
                f"construct graph edge {ref!r} has incompatible resource identities"
            )

    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise SystemExit("construct graph effect_dependencies entries must be objects")
        dependency_ref = construct_graph_string(dependency, "dependency_ref")
        if dependency_ref is None:
            raise SystemExit("construct graph effect dependency is missing dependency_ref")
        for field in ["upstream_node_id", "downstream_node_id"]:
            node_id = construct_graph_string(dependency, field)
            if node_id is None or node_id not in nodes_by_id:
                raise SystemExit(
                    f"construct graph effect dependency {dependency_ref!r} "
                    f"references unknown {field} {node_id!r}"
                )
        predicate = construct_graph_string(dependency, "predicate")
        if predicate not in {"succeeds", "fails", "completes"}:
            raise SystemExit(
                f"construct graph effect dependency {dependency_ref!r} has unknown predicate {predicate!r}"
            )


def validate_unique_refs(refs: list[str], label: str) -> None:
    seen: set[str] = set()
    duplicate: list[str] = []
    for ref in refs:
        if ref in seen and ref not in duplicate:
            duplicate.append(ref)
        seen.add(ref)
    if duplicate:
        preview = ", ".join(duplicate[:8])
        if len(duplicate) > 8:
            preview = f"{preview}, ... ({len(duplicate)} total)"
        raise SystemExit(f"construct graph {label} not unique: {preview}")


def derived_fact_predicates(
    artifact: dict[str, Any],
    artifact_name: str,
    owner_subsystem: str,
) -> dict[str, list[set[str]]]:
    facts = artifact.get("derived_facts")
    if not isinstance(facts, list):
        raise SystemExit(f"{artifact_name} is missing derived_facts")
    predicates: dict[str, list[set[str]]] = {}
    for index, fact in enumerate(facts):
        if not isinstance(fact, dict):
            raise SystemExit(f"{artifact_name} derived_facts[{index}] is not an object")
        if fact.get("owner_subsystem") != owner_subsystem:
            continue
        predicate = fact.get("predicate")
        if isinstance(predicate, str) and predicate:
            input_refs = fact.get("input_refs")
            if not isinstance(input_refs, list):
                raise SystemExit(
                    f"{artifact_name} derived_facts[{index}] is missing input_refs"
                )
            string_refs = [ref for ref in input_refs if isinstance(ref, str)]
            if len(string_refs) != len(set(string_refs)):
                raise SystemExit(
                    f"{artifact_name} derived_facts[{index}] has duplicate input_refs"
                )
            predicates.setdefault(predicate, []).append(set(string_refs))
    return predicates


def require_predicate(
    required: dict[str, set[str]],
    predicate: str,
    input_refs: list[str] | None = None,
) -> None:
    refs = required.setdefault(predicate, set())
    if input_refs:
        refs.update(ref for ref in input_refs if isinstance(ref, str))


def validate_required_predicates(
    predicates: dict[str, list[set[str]]],
    required: dict[str, set[str]],
    artifact_name: str,
) -> None:
    extra_predicates = sorted(predicate for predicate in predicates if predicate not in required)
    if extra_predicates:
        preview = ", ".join(extra_predicates[:8])
        if len(extra_predicates) > 8:
            preview = f"{preview}, ... ({len(extra_predicates)} total)"
        raise SystemExit(
            f"{artifact_name} derived_facts unexpected validator predicate(s): {preview}"
        )

    missing = sorted(predicate for predicate in required if predicate not in predicates)
    if missing:
        preview = ", ".join(missing[:8])
        if len(missing) > 8:
            preview = f"{preview}, ... ({len(missing)} total)"
        raise SystemExit(
            f"{artifact_name} derived_facts missing validator predicate(s): {preview}"
        )

    duplicate = sorted(
        predicate for predicate in required if len(predicates[predicate]) != 1
    )
    if duplicate:
        preview = ", ".join(duplicate[:8])
        if len(duplicate) > 8:
            preview = f"{preview}, ... ({len(duplicate)} total)"
        raise SystemExit(
            f"{artifact_name} derived_facts duplicate validator predicate(s): {preview}"
        )

    incomplete: list[str] = []
    unexpected: list[str] = []
    for predicate, expected_refs in sorted(required.items()):
        if not expected_refs:
            continue
        input_refs = predicates[predicate][0]
        if expected_refs == input_refs:
            continue
        missing_refs = sorted(expected_refs - input_refs)
        extra_refs = sorted(input_refs - expected_refs)
        if missing_refs:
            preview = ", ".join(missing_refs[:4])
            if len(missing_refs) > 4:
                preview = f"{preview}, ... ({len(missing_refs)} total)"
            incomplete.append(f"{predicate} missing {preview}")
        if extra_refs:
            preview = ", ".join(extra_refs[:4])
            if len(extra_refs) > 4:
                preview = f"{preview}, ... ({len(extra_refs)} total)"
            unexpected.append(f"{predicate} includes unexpected {preview}")
    if incomplete:
        preview = "; ".join(incomplete[:4])
        if len(incomplete) > 4:
            preview = f"{preview}; ... ({len(incomplete)} total)"
        raise SystemExit(
            f"{artifact_name} derived_facts validator predicate input_refs incomplete: {preview}"
        )
    if unexpected:
        preview = "; ".join(unexpected[:4])
        if len(unexpected) > 4:
            preview = f"{preview}; ... ({len(unexpected)} total)"
        raise SystemExit(
            f"{artifact_name} derived_facts validator predicate input_refs unexpected: {preview}"
        )


def validate_construct_graph_trace(
    graph: dict[str, Any],
    verifier_catalog: dict[str, Any],
) -> None:
    predicates = derived_fact_predicates(
        graph,
        "construct graph",
        "construct_graph_validator",
    )
    graph_id = graph.get("graph_id", "unknown")
    required: dict[str, set[str]] = {}
    nodes = graph.get("nodes", [])
    ports = graph.get("ports", [])
    edges = graph.get("edges", [])
    dependencies = graph.get("effect_dependencies", [])
    ports_by_id = {
        port.get("port_id"): port
        for port in ports
        if isinstance(port, dict) and isinstance(port.get("port_id"), str)
    }
    node_ids = [
        node_id
        for node_id in (node.get("node_id") for node in nodes)
        if isinstance(node_id, str) and node_id
    ]
    port_ids = [
        port_id
        for port_id in (port.get("port_id") for port in ports)
        if isinstance(port_id, str) and port_id
    ]
    edge_refs = [edge_ref(edge) for edge in edges]
    dependency_refs = [
        dependency_ref
        for dependency_ref in (
            dependency.get("dependency_ref") for dependency in dependencies
        )
        if isinstance(dependency_ref, str) and dependency_ref
    ]
    validate_unique_refs(node_ids, "node IDs")
    validate_unique_refs(port_ids, "port IDs")
    validate_unique_refs(edge_refs, "edge refs")
    validate_unique_refs(dependency_refs, "effect dependency refs")
    validate_construct_graph_inventory(graph, verifier_catalog)
    validate_construct_graph_cardinality(graph)
    validate_construct_graph_node_outputs(graph)
    validate_construct_graph_lifecycle_profiles(graph, verifier_catalog)
    require_predicate(
        required,
        f"validator.graph.node_ids_unique:{graph_id}",
        node_ids,
    )
    require_predicate(
        required,
        f"validator.graph.port_ids_unique:{graph_id}",
        port_ids,
    )
    require_predicate(
        required,
        f"validator.graph.edge_refs_unique:{graph_id}",
        edge_refs,
    )
    require_predicate(
        required,
        f"validator.graph.effect_dependency_refs_unique:{graph_id}",
        dependency_refs,
    )
    require_predicate(
        required,
        f"validator.graph.accepted:{graph_id}",
        [graph_id, *node_ids, *port_ids, *edge_refs, *dependency_refs],
    )
    for _, fact_id, ref_specs in ADEQUACY_FACTS:
        require_predicate(
            required,
            f"validator.graph.adequacy.{fact_id}:{graph_id}",
            graph_adequacy_refs(graph, ref_specs),
        )

    for node in nodes:
        node_id = node.get("node_id")
        if isinstance(node_id, str) and node_id:
            require_predicate(
                required,
                f"validator.node.profile:{node_id}",
                node_profile_refs(node),
            )
            require_predicate(
                required,
                f"validator.node.interfaces:{node_id}",
                node_interface_refs(node),
            )
            require_predicate(
                required,
                f"validator.node.capabilities:{node_id}",
                node_capability_refs(node),
            )
            lowering_output_kind = node.get("lowering_output_kind")
            if not isinstance(lowering_output_kind, str) or not lowering_output_kind:
                lowering_output_kind = "unknown"
            require_predicate(
                required,
                f"validator.node.output:{node_id}:{lowering_output_kind}",
                node_output_refs(node),
            )
            refs = [node_id]
            refs.extend(
                ref
                for ref in node.get("required_ports", [])
                if isinstance(ref, str) and ref
            )
            refs.extend(
                ref
                for ref in node.get("produced_ports", [])
                if isinstance(ref, str) and ref
            )
            require_predicate(
                required,
                f"validator.node.ports_consistent:{node_id}",
                refs,
            )

    edge_objects_by_required: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        required_port_id = edge.get("required_port_id")
        if isinstance(required_port_id, str) and required_port_id:
            edge_objects_by_required.setdefault(required_port_id, []).append(edge)

    for port in ports:
        port_id = port.get("port_id")
        if not isinstance(port_id, str) or not port_id:
            continue
        owner_node_id = port.get("owner_node_id")
        refs = [port_id]
        if isinstance(owner_node_id, str) and owner_node_id:
            refs.append(owner_node_id)
        require_predicate(
            required,
            f"validator.port.profile:{port_id}",
            port_profile_refs(port),
        )
        require_predicate(
            required,
            f"validator.port.owner_consistent:{port_id}",
            refs,
        )
        if port.get("direction") == "required":
            cardinality = port.get("cardinality", "unknown")
            require_predicate(
                required,
                f"validator.cardinality.{cardinality}.satisfied:{port_id}",
                cardinality_fact_refs(port, edge_objects_by_required.get(port_id, [])),
            )

    for edge in edges:
        ref = edge_ref(edge)
        required_port = ports_by_id.get(edge.get("required_port_id"))
        provided_port = ports_by_id.get(edge.get("provided_port_id"))
        input_refs = edge_validation_refs(edge, required_port, provided_port)
        for predicate in [
            "validator.edge.endpoints_valid",
            "validator.edge.kind_compatible",
            "validator.edge.type_compatible",
            "validator.edge.phase_compatible",
            "validator.edge.version_compatible",
            "validator.edge.resource_compatible",
        ]:
            require_predicate(required, f"{predicate}:{ref}", input_refs)

    for dependency in dependencies:
        dependency_ref = dependency.get("dependency_ref")
        if not isinstance(dependency_ref, str) or not dependency_ref:
            continue
        input_refs = [dependency_ref]
        for key in ["upstream_node_id", "predicate", "downstream_node_id"]:
            value = dependency.get(key)
            if isinstance(value, str) and value:
                input_refs.append(value)
        for predicate in [
            "validator.effect_dependency.endpoints_valid",
            "validator.effect_dependency.predicate_valid",
            "validator.effect_dependency.source_span_preserved",
        ]:
            require_predicate(required, f"{predicate}:{dependency_ref}", input_refs)

    validate_required_predicates(predicates, required, "construct graph")


def string_field_refs(value: dict[str, Any], keys: list[str]) -> list[str]:
    refs: list[str] = []
    for key in keys:
        ref = value.get(key)
        if isinstance(ref, str) and ref:
            refs.append(ref)
    return refs


def string_array_refs(value: dict[str, Any], key: str) -> list[str]:
    return [
        ref for ref in value.get(key, []) if isinstance(ref, str) and ref
    ]


def interface_refs(node: dict[str, Any], key: str) -> list[str]:
    refs: list[str] = []
    for interface in node.get(key, []):
        if not isinstance(interface, dict):
            continue
        refs.extend(
            string_field_refs(
                interface,
                ["kind", "name", "type", "phase", "cardinality"],
            )
        )
    return refs


def node_profile_refs(node: dict[str, Any]) -> list[str]:
    return string_field_refs(
        node,
        [
            "node_id",
            "construct_id",
            "construct_family",
            "lowering_class",
            "lifecycle_profile",
            "owner",
            "lowering_output_kind",
        ],
    )


def node_interface_refs(node: dict[str, Any]) -> list[str]:
    refs = string_field_refs(node, ["node_id"])
    refs.extend(string_array_refs(node, "required_ports"))
    refs.extend(string_array_refs(node, "produced_ports"))
    refs.extend(interface_refs(node, "declared_required_interfaces"))
    refs.extend(interface_refs(node, "declared_provided_interfaces"))
    return refs


def node_capability_refs(node: dict[str, Any]) -> list[str]:
    refs = string_field_refs(node, ["node_id"])
    refs.extend(string_array_refs(node, "required_capabilities"))
    refs.extend(string_array_refs(node, "lowered_effect_capabilities"))
    return refs


def node_output_refs(node: dict[str, Any]) -> list[str]:
    refs = string_field_refs(node, ["node_id", "lowering_output_kind"])
    refs.extend(string_array_refs(node, "allowed_core_object_kinds"))
    refs.extend(string_array_refs(node, "allowed_runtime_entrypoints"))
    return refs


def edge_validation_refs(
    edge: dict[str, Any],
    required_port: dict[str, Any] | None,
    provided_port: dict[str, Any] | None,
) -> list[str]:
    ref = edge_ref(edge)
    refs = [ref]
    for key in ["required_port_id", "provider_node_id", "provided_port_id"]:
        value = edge.get(key)
        if isinstance(value, str) and value:
            refs.append(value)
    refs.extend(optional_labeled_ref(ref, "resolution_reason", edge.get("resolution_reason")))
    for evidence in string_array_refs(edge, "evidence"):
        refs.append(f"{ref}#evidence:{evidence}")
    if isinstance(required_port, dict):
        refs.extend(port_validation_refs("required", required_port))
    if isinstance(provided_port, dict):
        refs.extend(port_validation_refs("provided", provided_port))
    return refs


def port_validation_refs(role: str, port: dict[str, Any]) -> list[str]:
    port_id = port.get("port_id")
    if not isinstance(port_id, str) or not port_id:
        port_id = "unknown"
    refs: list[str] = []
    for field in [
        "owner_node_id",
        "direction",
        "kind",
        "type",
        "phase",
        "contract_version",
        "cardinality",
    ]:
        refs.extend(optional_labeled_ref(port_id, f"{role}.{field}", port.get(field)))
    resource_identity = port.get("resource_identity")
    if not isinstance(resource_identity, str) or not resource_identity:
        resource_identity = "<none>"
    refs.append(f"{port_id}#{role}.resource_identity:{resource_identity}")
    return refs


def port_profile_refs(port: dict[str, Any]) -> list[str]:
    port_id = port.get("port_id")
    if not isinstance(port_id, str) or not port_id:
        port_id = "unknown"
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
        refs.extend(optional_labeled_ref(port_id, field, port.get(field)))
    resource_identity = port.get("resource_identity")
    if not isinstance(resource_identity, str) or not resource_identity:
        resource_identity = "<none>"
    refs.append(f"{port_id}#resource_identity:{resource_identity}")
    return refs


def optional_labeled_ref(owner: str, label: str, value: Any) -> list[str]:
    if isinstance(value, str) and value:
        return [f"{owner}#{label}:{value}"]
    return []


def maude_graph_node_list(node_symbols: list[str]) -> str:
    result = "noGraphNodes"
    for node_symbol in reversed(node_symbols):
        result = f"graphNodeCons({node_symbol}, {result})"
    return result


def maude_port_list(port_symbols: list[str]) -> str:
    result = "noPorts"
    for port_symbol in reversed(port_symbols):
        result = f"portCons({port_symbol}, {result})"
    return result


def maude_port_kind(symbols: SymbolTable, kind: str) -> str:
    return PORT_KIND.get(kind) or symbols.symbol("PortKind", "portKind", kind)


def maude_phase(symbols: SymbolTable, phase: str) -> str:
    return PHASE.get(phase) or symbols.symbol("PortPhase", "phase", phase)


def maude_cardinality(cardinality: str) -> str:
    if cardinality not in CARDINALITY:
        raise SystemExit(f"unsupported port cardinality {cardinality!r}")
    return CARDINALITY[cardinality]


def maude_lowered_kind(symbols: SymbolTable, kind: str) -> str:
    return symbols.symbol("LoweredKind", "lowered", kind)


def maude_type(symbols: SymbolTable, type_name: str) -> str:
    return symbols.symbol("TypeId", "type", type_name)


def maude_version(symbols: SymbolTable, version: str) -> str:
    return symbols.symbol("ContractVersion", "version", version)


def maude_capability(symbols: SymbolTable, capability: str) -> str:
    return symbols.symbol("CapabilityId", "cap", capability)


def maude_resource(symbols: SymbolTable, resource: str) -> str:
    return symbols.symbol("ResourceId", "resource", resource)


def print_search(title: str, facts: list[str], target: str) -> None:
    print(f"--- {title}")
    print("search [1] in WHIPPLESCRIPT-GENERATED-CONSTRUCT-GRAPH :")
    print("  " + "\n  ".join(facts))
    print("  =>*")
    print("  C:Cfg")
    print(f"  {target} .")
    print()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--platform-catalog",
        type=Path,
        default=None,
        help="compiler-emitted platform catalog from `whip package catalog`",
    )
    parser.add_argument(
        "--entry-index",
        type=int,
        default=None,
        help="zero-based entry to lower when the input is a multi-entry check report or verified artifact bundle",
    )
    parser.add_argument("check_report", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    verifier_catalog = load_platform_construct_catalog(root, args.platform_catalog)
    graph = load_construct_graph(
        root,
        verifier_catalog,
        args.check_report,
        args.entry_index,
    )
    symbols = SymbolTable()

    graph_symbol = symbols.symbol("GraphId", "graph", str(graph["graph_id"]))
    nodes = graph.get("nodes", [])
    ports = graph.get("ports", [])
    edges = graph.get("edges", [])
    nodes_by_id = {node["node_id"]: node for node in nodes}
    ports_by_id = {port["port_id"]: port for port in ports}
    node_symbols = {
        node_id: symbols.symbol("GraphNode", "node", node_id)
        for node_id in nodes_by_id
    }
    port_symbols = {
        port_id: symbols.symbol("PortId", "port", port_id)
        for port_id in ports_by_id
    }
    edges_by_required: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        edges_by_required.setdefault(edge["required_port_id"], []).append(edge)

    def port_fact(port_id: str) -> str:
        port = ports_by_id[port_id]
        port_symbol = port_symbols[port_id]
        return (
            "port("
            f"{port_symbol}, "
            f"{maude_port_kind(symbols, port['kind'])}, "
            f"{maude_type(symbols, port['type'])}, "
            f"{maude_phase(symbols, port['phase'])}, "
            f"{maude_version(symbols, port['contract_version'])}, "
            f"{maude_cardinality(port['cardinality'])}"
            ")"
        )

    def port_scope_fact(port_id: str) -> str:
        port = ports_by_id[port_id]
        port_symbol = port_symbols[port_id]
        if port.get("resource_identity") is None:
            return f"portUnscoped({port_symbol})"
        return f"portResource({port_symbol}, {maude_resource(symbols, port['resource_identity'])})"

    def node_contract_facts(node_id: str, include_graph_membership: bool = True) -> list[str]:
        node = nodes_by_id[node_id]
        node_symbol = node_symbols[node_id]
        required = [port_symbols[port_id] for port_id in node.get("required_ports", [])]
        produced = [port_symbols[port_id] for port_id in node.get("produced_ports", [])]
        facts = [
            f"nodeFamilyAccepted({node_symbol})",
            f"nodeLoweringAccepted({node_symbol})",
            f"nodeShapeUnique({node_symbol})",
            f"noHiddenNodeBehavior({node_symbol})",
            f"nodeFactsConsistent({node_symbol})",
            f"nodeNeeds({node_symbol}, {maude_port_list(required)})",
            f"nodeProduces({node_symbol}, {maude_port_list(produced)})",
            f"loweringOutput({node_symbol}, {maude_lowered_kind(symbols, node['lowering_output_kind'])})",
            f"allowedLoweringOutput({maude_lowered_kind(symbols, node['lowering_output_kind'])})",
            f"singleLoweringOutput({node_symbol})",
        ]
        if include_graph_membership:
            facts.insert(0, f"graphContainsNode({graph_symbol}, {node_symbol})")
        if node.get("required_capabilities"):
            for capability in node["required_capabilities"]:
                capability_symbol = maude_capability(symbols, capability)
                effect_symbol = symbols.symbol("EffectId", "effect", f"{node_id}:{capability}")
                facts.extend([
                    f"nodeRequiresCapability({node_symbol}, {capability_symbol})",
                    f"declaredCapability({capability_symbol})",
                    f"loweredEffectRequiresCapability({node_symbol}, {effect_symbol}, {capability_symbol})",
                ])
        else:
            facts.append(f"noCapabilityRequirements({node_symbol})")
        for port_symbol in produced:
            facts.extend([
                f"providesPort({node_symbol}, {port_symbol})",
                f"producedPortAllowed({node_symbol}, {port_symbol})",
            ])
        return facts

    def provider_port_facts(provider_node_id: str) -> list[str]:
        provider_node = nodes_by_id[provider_node_id]
        provider_symbol = node_symbols[provider_node_id]
        produced = [
            port_symbols[port_id]
            for port_id in provider_node.get("produced_ports", [])
        ]
        facts = [
            f"nodeProduces({provider_symbol}, {maude_port_list(produced)})",
        ]
        for port_symbol in produced:
            facts.extend([
                f"providesPort({provider_symbol}, {port_symbol})",
                f"producedPortAllowed({provider_symbol}, {port_symbol})",
            ])
        return facts

    def edge_facts(edge: dict[str, Any]) -> list[str]:
        required_port = ports_by_id[edge["required_port_id"]]
        provided_port = ports_by_id[edge["provided_port_id"]]
        required_node = node_symbols[required_port["owner_node_id"]]
        provider_node = node_symbols[edge["provider_node_id"]]
        required_port_symbol = port_symbols[edge["required_port_id"]]
        provided_port_symbol = port_symbols[edge["provided_port_id"]]
        cardinality = required_port["cardinality"]
        facts = provider_port_facts(edge["provider_node_id"])
        facts.extend([
            port_fact(edge["required_port_id"]),
            port_fact(edge["provided_port_id"]),
            port_scope_fact(edge["required_port_id"]),
            port_scope_fact(edge["provided_port_id"]),
            f"resolvesPort({required_node}, {required_port_symbol}, {provider_node}, {provided_port_symbol})",
            f"resolutionFactsConsistent({required_node}, {required_port_symbol})",
            f"kindCompatible({maude_port_kind(symbols, required_port['kind'])}, {maude_port_kind(symbols, provided_port['kind'])})",
            f"typeAssignable({maude_type(symbols, provided_port['type'])}, {maude_type(symbols, required_port['type'])})",
            f"phaseCompatible({maude_phase(symbols, provided_port['phase'])}, {maude_phase(symbols, required_port['phase'])})",
            f"versionCompatible({maude_version(symbols, provided_port['contract_version'])}, {maude_version(symbols, required_port['contract_version'])})",
            f"resourceCompatible({required_port_symbol}, {provided_port_symbol})",
        ])
        if cardinality in {"exactly-one", "optional-one"}:
            facts.extend([
                f"uniqueResolution({required_node}, {required_port_symbol})",
                f"uniqueResolvedPort({required_node}, {required_port_symbol}, {provider_node}, {provided_port_symbol})",
            ])
        if cardinality in {"many", "named-many"}:
            facts.extend([
                f"manyResolutionOrderClosed({required_node}, {required_port_symbol})",
                f"resolutionOrder({required_node}, {required_port_symbol}, {provider_node}, {provided_port_symbol})",
            ])
        if cardinality == "named-many":
            resource_key = edge.get("resource_key")
            if not resource_key:
                raise SystemExit(f"named-many edge {edge} missing resource_key")
            resource_symbol = maude_resource(symbols, resource_key)
            facts.append(
                f"namedResolutionKeyed({required_node}, {required_port_symbol}, {provider_node}, {provided_port_symbol}, {resource_symbol})"
            )
        return facts

    def absent_resolution_facts(port_id: str) -> list[str]:
        port = ports_by_id[port_id]
        owner_node = node_symbols[port["owner_node_id"]]
        port_symbol = port_symbols[port_id]
        cardinality = port["cardinality"]
        facts: list[str] = []
        if cardinality in {"optional-one", "many", "named-many"}:
            facts.append(f"resolutionAbsent({owner_node}, {port_symbol})")
            facts.append(f"resolutionFactsConsistent({owner_node}, {port_symbol})")
        if cardinality in {"many", "named-many"}:
            facts.append(f"manyResolutionOrderClosed({owner_node}, {port_symbol})")
        return facts

    node_searches: list[tuple[str, list[str], str]] = []
    for node_id, node_symbol in node_symbols.items():
        node = nodes_by_id[node_id]
        facts = node_contract_facts(node_id)
        for port_id in node.get("required_ports", []):
            facts.append(port_fact(port_id))
            facts.append(port_scope_fact(port_id))
            for edge in edges_by_required.get(port_id, []):
                facts.extend(edge_facts(edge))
            if port_id not in edges_by_required:
                facts.extend(absent_resolution_facts(port_id))
        for port_id in node.get("produced_ports", []):
            facts.append(port_fact(port_id))
            facts.append(port_scope_fact(port_id))
        node_searches.append((
            f"Generated node acceptance for {node_id}.",
            facts,
            f"nodeAccepted({graph_symbol}, {node_symbol})",
        ))

    edge_searches: list[tuple[str, list[str], str]] = []
    for edge in edges:
        required_port = ports_by_id[edge["required_port_id"]]
        required_node = node_symbols[required_port["owner_node_id"]]
        provider_node = node_symbols[edge["provider_node_id"]]
        required_port_symbol = port_symbols[edge["required_port_id"]]
        provided_port_symbol = port_symbols[edge["provided_port_id"]]
        edge_searches.append((
            f"Generated edge acceptance for {edge['required_port_id']} -> {edge['provided_port_id']}.",
            edge_facts(edge),
            f"edgeAccepted({required_node}, {required_port_symbol}, {provider_node}, {provided_port_symbol})",
        ))

    graph_facts = [
        f"graphNodes({graph_symbol}, {maude_graph_node_list(list(node_symbols.values()))})",
    ]
    graph_facts.extend(
        f"nodeAccepted({graph_symbol}, {node_symbol})"
        for node_symbol in node_symbols.values()
    )

    print(f"load {root / 'models/maude/kernel.maude'}")
    print(f"load {root / 'models/maude/construct-grammar.maude'}")
    print(f"load {root / 'models/maude/construct-graph.maude'}")
    print()
    print("mod WHIPPLESCRIPT-GENERATED-CONSTRUCT-GRAPH is")
    print("  including WHIPPLESCRIPT-CONSTRUCT-GRAPH .")
    for line in symbols.emit_ops():
        print(line)
    print("endm")
    print()
    print("--- Generated from whip --json check construct_graph.")
    for title, facts, target in [*node_searches, *edge_searches]:
        print_search(title, facts, target)
    print_search(
        "Generated graph aggregation from accepted nodes.",
        graph_facts,
        f"graphAccepted({graph_symbol})",
    )
    print_search(
        "Generated accepted program from admitted graph and adequacy evidence.",
        [
            *graph_facts,
            *(f"{maude_fact}({graph_symbol})" for maude_fact, _, _ in ADEQUACY_FACTS),
        ],
        f"acceptedProgram({graph_symbol})",
    )


if __name__ == "__main__":
    main()
