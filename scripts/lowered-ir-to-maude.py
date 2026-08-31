#!/usr/bin/env python3
"""Lower a verified/check/compile lowered_ir_report artifact into Maude obligations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

from artifact_admission import (
    CURRENT_SUPPORTED_CORE_OBJECT_KINDS,
    CURRENT_SUPPORTED_RUNTIME_ENTRYPOINTS,
    LOWERING_CLASS,
    STATIC_GUARANTEE_FACTS,
    SymbolTable,
    canonical_json,
    catalog_lowerings,
    derived_fact_predicates,
    is_sha256_digest,
    is_stable_digest,
    load_platform_construct_catalog,
    maude_graph_node_list,
    require_predicate,
    required_string,
    stable_hash_hex,
    validate_contract_registry_shape,
    validate_empty_diagnostics,
    validate_package_contract_platform,
    validate_package_contract_spine,
    validate_required_predicates,
)

try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError, ValidationError
except Exception as exc:
    raise SystemExit(
        "python jsonschema package is required; run under `nix develop` or "
        f"install `requirements-dev.txt`: {exc}"
    )


CONSTRUCT_FAMILY = {
    "effect_operation": "effectOperation",
    "effect_contract": "effectContract",
    "declaration_block": "declarationBlock",
    "rule": "ruleConstruct",
    "assertion": "assertionConstruct",
    "signal_source": "eventSourceConstruct",
    "projection_read": "projectionReadConstruct",
    "signal_emit_operation": "eventEmitOperation",
    "resource_operation": "resourceOperation",
    "provider_declaration": "providerDeclaration",
    "projection_declaration": "projectionDeclaration",
    "policy_clause": "policyClause",
}

CORE_KIND = {
    "fact": "coreFactKind",
    "event": "coreEventKind",
    "signal_source": "coreEventSourceKind",
    "schedule": "coreScheduleKind",
    "effect": "coreEffectKind",
    "rule": "coreRuleKind",
    "dependency": "coreDependencyKind",
    "projection": "coreProjectionKind",
    "assertion": "coreAssertionKind",
    "diagnostic": "coreDiagnosticKind",
}

RUNTIME_ENTRYPOINT_BY_KIND = {
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

RUNTIME_ENTRYPOINT_KIND = {
    "fact_record": "factRecord",
    "event_record": "eventRecord",
    "signal_source_template": "eventSourceTemplateEntrypoint",
    "schedule_template": "scheduleTemplateEntrypoint",
    "effect_graph_template": "effectGraphTemplate",
    "rule_template": "ruleTemplate",
    "effect_dependency_template": "effectDependencyTemplate",
    "event_projection": "eventProjection",
    "assertion_check": "assertionCheck",
    "diagnostic_record": "diagnosticRecord",
}

FORBIDDEN_RUNTIME_OBJECT_KINDS = {
    "run",
    "claim",
    "terminal",
    "cancellation",
    "cancellation_request",
    "cancellation_ack",
    "retry",
    "lease",
    "provider_evidence",
    "provider_run",
}

FORBIDDEN_RUNTIME_ENTRYPOINTS = {
    "run_record",
    "claim_record",
    "terminal_status",
    "cancellation_request",
    "cancellation_ack",
    "retry_record",
    "lease_recovery",
    "provider_evidence",
    "provider_run",
}


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


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_construct_graph_admission(
    root: Path,
    graph: dict[str, Any],
    verifier_catalog: dict[str, Any],
) -> None:
    construct_bridge = load_module(
        root / "scripts" / "construct-graph-to-maude.py",
        "construct_graph_bridge_for_lowered_ir",
    )
    construct_bridge.validate_construct_graph_trace(graph, verifier_catalog)


def validate_report_entry_identity(
    root: Path,
    verifier_catalog: dict[str, Any],
    entry: dict[str, Any],
    graph: dict[str, Any],
    lowered: dict[str, Any],
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

    lowered_graph_id = lowered.get("graph_id")
    accepted_program_digest = lowered.get("accepted_program_digest")
    expected_program_digest = hashlib.sha256(
        f"{lowered_graph_id}\n{snapshot}".encode("utf-8")
    ).hexdigest()
    if accepted_program_digest != expected_program_digest:
        raise SystemExit(
            f"{label} lowered_ir_report.accepted_program_digest does not match "
            "graph_id + snapshot"
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


def load_artifacts(
    root: Path,
    verifier_catalog: dict[str, Any],
    report_path: Path,
    entry_index: int | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entry, label = load_report_entry(root, report_path, entry_index)
    graph = entry.get("construct_graph")
    lowered = entry.get("lowered_ir_report")
    if not isinstance(graph, dict):
        raise SystemExit(f"{label} has no construct_graph")
    if not isinstance(lowered, dict):
        raise SystemExit(f"{label} has no lowered_ir_report")
    validate_report_entry_identity(root, verifier_catalog, entry, graph, lowered, label)
    validate_json_schema(
        root,
        "construct_graph_v0.schema.json",
        graph,
        "construct graph",
    )
    validate_json_schema(
        root,
        "lowered_ir_report_v0.schema.json",
        lowered,
        "lowered IR report",
    )
    graph_errors = [
        diag
        for diag in graph.get("diagnostics", [])
        if diag.get("severity") == "error"
    ]
    lowered_errors = [
        diag
        for diag in lowered.get("diagnostics", [])
        if diag.get("severity") == "error"
    ]
    validate_artifact_identity(graph, lowered)
    if graph_errors:
        codes = ", ".join(str(diag.get("code", "unknown")) for diag in graph_errors)
        raise SystemExit(f"construct graph has validator errors: {codes}")
    validate_construct_graph_admission(root, graph, verifier_catalog)
    if lowered_errors:
        codes = ", ".join(str(diag.get("code", "unknown")) for diag in lowered_errors)
        raise SystemExit(f"lowered IR report has validator errors: {codes}")
    validate_lowered_ir_trace(graph, lowered)
    return graph, lowered


def validate_artifact_identity(graph: dict[str, Any], lowered: dict[str, Any]) -> None:
    for field in ["graph_id", "source_digest", "package_lock_digest"]:
        graph_value = graph.get(field)
        lowered_value = lowered.get(field)
        if isinstance(graph_value, str) and graph_value and graph_value == lowered_value:
            continue
        raise SystemExit(
            "lowered IR report "
            f"{field} {lowered_value!r} does not match construct graph "
            f"{field} {graph_value!r}"
        )


def edge_ref(required_port_id: str, provided_port_id: str) -> str:
    return f"{required_port_id}->{provided_port_id}"


def edge_for_lowering(
    edges_by_ref: dict[str, dict[str, Any]],
    required_port_id: str,
    provided_port_id: str,
) -> dict[str, Any]:
    ref = edge_ref(required_port_id, provided_port_id)
    edge = edges_by_ref.get(ref)
    if edge is None:
        raise SystemExit(f"unknown edge lowering ref {ref!r}")
    return edge


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
        raise SystemExit(f"lowered IR report {label} not unique: {preview}")


def string_array(value: dict[str, Any], key: str) -> list[str]:
    array = value.get(key)
    if not isinstance(array, list):
        return []
    return [item for item in array if isinstance(item, str) and item]


def optional_string_ref(value: dict[str, Any], key: str) -> list[str]:
    item = value.get(key)
    if isinstance(item, str) and item:
        return [item]
    return []


def lowered_report_field_ref(lowered: dict[str, Any], field: str) -> str:
    value = lowered.get(field)
    if not isinstance(value, str) or not value:
        value = "unknown"
    return f"lowered_ir.root.{field}:{value}"


def graph_determinism_refs(lowered: dict[str, Any]) -> list[str]:
    return [
        lowered_report_field_ref(lowered, field)
        for field in [
            "graph_id",
            "source_digest",
            "package_lock_digest",
            "accepted_program_digest",
            "lowerer_version",
        ]
    ]


def graph_report_root_refs(lowered: dict[str, Any]) -> list[str]:
    return [
        lowered_report_field_ref(lowered, field)
        for field in [
            "schema",
            "graph_id",
            "source_digest",
            "package_lock_digest",
            "accepted_program_digest",
            "lowerer_version",
        ]
    ]


def lowered_inventory_ref(kind: str, item_ref: str) -> str:
    return f"lowered_ir.inventory.{kind}:{item_ref}"


def lowered_runtime_object_ref(
    object_id: str,
    object_kind: str,
    runtime_entrypoint: str,
) -> str:
    return (
        f"lowered_ir.runtime_boundary."
        f"{object_id}:{object_kind}:{runtime_entrypoint}"
    )


def node_preservation_refs(graph_id: str, node_id: str, lowering: dict[str, Any]) -> list[str]:
    refs = [graph_id, node_id]
    refs.extend(optional_string_ref(lowering, "lowering_class"))
    for key in [
        "produced_core_object_refs",
        "preserved_source_span_refs",
        "preserved_resource_refs",
        "preserved_capability_refs",
        "preserved_version_refs",
        "preserved_cardinality_refs",
        "preserved_provenance_refs",
        "preserved_terminal_binding_refs",
    ]:
        refs.extend(string_array(lowering, key))
    return refs


NODE_PRESERVATION_COMPONENT_FIELDS = [
    ("lowering_class", "lowering_class"),
    ("produced_core_objects", "produced_core_object_refs"),
    ("source_span", "preserved_source_span_refs"),
    ("resource", "preserved_resource_refs"),
    ("capability", "preserved_capability_refs"),
    ("version", "preserved_version_refs"),
    ("cardinality", "preserved_cardinality_refs"),
    ("provenance", "preserved_provenance_refs"),
    ("terminal_binding", "preserved_terminal_binding_refs"),
]


EDGE_PRESERVATION_COMPONENT_FIELDS = [
    ("required_port", "required_port_id"),
    ("provided_port", "provided_port_id"),
    ("core_relation", "core_relation_ref"),
    ("produced_core_objects", "produced_core_object_refs"),
    ("type", "preserved_type_refs"),
    ("resource", "preserved_resource_refs"),
    ("capability", "preserved_capability_refs"),
    ("version", "preserved_version_refs"),
    ("span", "preserved_span_refs"),
    ("cardinality", "preserved_cardinality_refs"),
    ("provenance", "preserved_provenance_refs"),
]


DEPENDENCY_PRESERVATION_COMPONENT_FIELDS = [
    ("produced_core_objects", "produced_core_object_refs"),
    ("effect", "preserved_effect_refs"),
    ("predicate", "preserved_predicate"),
    ("span", "preserved_span_refs"),
    ("provenance", "preserved_provenance_refs"),
]


NODE_LIFECYCLE_INPUT_COMPONENT_FIELDS = [
    "lowering_class",
    "construct_family",
    "lifecycle_profile",
    "produced_core_objects",
    "object_kinds",
    "runtime_entrypoints",
]


NODE_OUTPUT_COMPAT_COMPONENT_FIELDS = [
    "allowed_core_object_kinds",
    "allowed_runtime_entrypoints",
    "produced_core_objects",
    "object_kinds",
    "runtime_entrypoints",
]


def node_preservation_component_refs(
    graph_id: str,
    node_id: str,
    lowering: dict[str, Any],
    field: str,
) -> list[str]:
    refs = [graph_id, node_id]
    if field == "lowering_class":
        refs.extend(optional_string_ref(lowering, field))
    else:
        refs.extend(string_array(lowering, field))
    return refs


def node_output_compat_refs(
    graph_id: str,
    node_id: str,
    lowering: dict[str, Any],
    graph_node: dict[str, Any] | None,
    core_objects_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    refs = [graph_id, node_id]
    if isinstance(graph_node, dict):
        refs.extend(string_array(graph_node, "allowed_core_object_kinds"))
        refs.extend(string_array(graph_node, "allowed_runtime_entrypoints"))
    for object_id in string_array(lowering, "produced_core_object_refs"):
        refs.append(object_id)
        obj = core_objects_by_id.get(object_id)
        if not isinstance(obj, dict):
            continue
        refs.extend(optional_string_ref(obj, "object_kind"))
        refs.extend(optional_string_ref(obj, "runtime_entrypoint"))
    return refs


def node_output_compat_component_refs(
    graph_id: str,
    node_id: str,
    lowering: dict[str, Any],
    graph_node: dict[str, Any] | None,
    core_objects_by_id: dict[str, dict[str, Any]],
    field: str,
) -> list[str]:
    refs = [graph_id, node_id]
    if field == "allowed_core_object_kinds":
        if isinstance(graph_node, dict):
            refs.extend(string_array(graph_node, "allowed_core_object_kinds"))
    elif field == "allowed_runtime_entrypoints":
        if isinstance(graph_node, dict):
            refs.extend(string_array(graph_node, "allowed_runtime_entrypoints"))
    elif field == "produced_core_objects":
        refs.extend(string_array(lowering, "produced_core_object_refs"))
    elif field == "object_kinds":
        for object_id in string_array(lowering, "produced_core_object_refs"):
            refs.append(object_id)
            obj = core_objects_by_id.get(object_id)
            if isinstance(obj, dict):
                refs.extend(optional_string_ref(obj, "object_kind"))
    elif field == "runtime_entrypoints":
        for object_id in string_array(lowering, "produced_core_object_refs"):
            refs.append(object_id)
            obj = core_objects_by_id.get(object_id)
            if isinstance(obj, dict):
                refs.extend(optional_string_ref(obj, "runtime_entrypoint"))
    return refs


def node_lifecycle_input_refs(
    graph_id: str,
    node_id: str,
    lowering: dict[str, Any],
    graph_node: dict[str, Any] | None,
    core_objects_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    refs = [graph_id, node_id]
    refs.extend(optional_string_ref(lowering, "lowering_class"))
    if isinstance(graph_node, dict):
        refs.extend(optional_string_ref(graph_node, "construct_family"))
        refs.extend(optional_string_ref(graph_node, "lifecycle_profile"))
    for object_id in string_array(lowering, "produced_core_object_refs"):
        refs.append(object_id)
        obj = core_objects_by_id.get(object_id)
        if not isinstance(obj, dict):
            continue
        refs.extend(optional_string_ref(obj, "object_kind"))
        refs.extend(optional_string_ref(obj, "runtime_entrypoint"))
    return refs


def node_lifecycle_input_component_refs(
    graph_id: str,
    node_id: str,
    lowering: dict[str, Any],
    graph_node: dict[str, Any] | None,
    core_objects_by_id: dict[str, dict[str, Any]],
    field: str,
) -> list[str]:
    refs = [graph_id, node_id]
    if field == "lowering_class":
        refs.extend(optional_string_ref(lowering, "lowering_class"))
    elif field == "construct_family":
        if isinstance(graph_node, dict):
            refs.extend(optional_string_ref(graph_node, "construct_family"))
    elif field == "lifecycle_profile":
        if isinstance(graph_node, dict):
            refs.extend(optional_string_ref(graph_node, "lifecycle_profile"))
    elif field == "produced_core_objects":
        refs.extend(string_array(lowering, "produced_core_object_refs"))
    elif field == "object_kinds":
        for object_id in string_array(lowering, "produced_core_object_refs"):
            refs.append(object_id)
            obj = core_objects_by_id.get(object_id)
            if isinstance(obj, dict):
                refs.extend(optional_string_ref(obj, "object_kind"))
    elif field == "runtime_entrypoints":
        for object_id in string_array(lowering, "produced_core_object_refs"):
            refs.append(object_id)
            obj = core_objects_by_id.get(object_id)
            if isinstance(obj, dict):
                refs.extend(optional_string_ref(obj, "runtime_entrypoint"))
    return refs


def core_object_entrypoint_refs(
    graph_id: str,
    object_id: str,
    obj: dict[str, Any],
    object_kind: str,
    runtime_entrypoint: str,
) -> list[str]:
    refs = [graph_id, object_id, object_kind, runtime_entrypoint]
    entrypoint_refs = obj.get("entrypoint_refs")
    if isinstance(entrypoint_refs, dict):
        for key, value in sorted(entrypoint_refs.items()):
            if isinstance(key, str) and isinstance(value, str):
                refs.append(f"{object_id}#entrypoint_refs.{key}:{value}")
    return refs


def validate_node_output_compatibility(
    node_id: str,
    lowering: dict[str, Any],
    graph_nodes_by_id: dict[str, dict[str, Any]],
    core_objects_by_id: dict[str, dict[str, Any]],
) -> None:
    node = graph_nodes_by_id.get(node_id)
    if not isinstance(node, dict):
        return
    allowed_kinds = set(string_array(node, "allowed_core_object_kinds"))
    allowed_entrypoints = set(string_array(node, "allowed_runtime_entrypoints"))
    for object_id in string_array(lowering, "produced_core_object_refs"):
        obj = core_objects_by_id.get(object_id)
        if not isinstance(obj, dict):
            continue
        object_kind = obj.get("object_kind")
        runtime_entrypoint = obj.get("runtime_entrypoint")
        if isinstance(object_kind, str) and object_kind not in allowed_kinds:
            raise SystemExit(
                "lowered IR report node "
                f"{node_id!r} produced core object {object_id!r} kind "
                f"{object_kind!r} not allowed by construct graph output vocabulary"
            )
        if (
            isinstance(runtime_entrypoint, str)
            and runtime_entrypoint not in allowed_entrypoints
        ):
            raise SystemExit(
                "lowered IR report node "
                f"{node_id!r} produced core object {object_id!r} runtime entrypoint "
                f"{runtime_entrypoint!r} not allowed by construct graph output vocabulary"
            )


def lowered_ir_owner_token(owner_kind: str, owner_ref: str) -> str:
    if owner_kind == "node":
        return f"node:{owner_ref}"
    if owner_kind == "edge":
        return f"edge:{owner_ref}"
    if owner_kind == "dependency":
        return f"dependency:{owner_ref}"
    raise SystemExit(
        f"lowered IR report core object owner kind {owner_kind!r} is unsupported"
    )


def validate_lowered_ir_core_object_kind_and_entrypoint(obj: dict[str, Any]) -> None:
    object_id = obj.get("object_id")
    object_kind = obj.get("object_kind")
    runtime_entrypoint = obj.get("runtime_entrypoint")
    if not isinstance(object_id, str) or not object_id:
        raise SystemExit("lowered IR report core object is missing object_id")
    if not isinstance(object_kind, str) or not object_kind:
        raise SystemExit(f"lowered IR object {object_id!r} is missing object_kind")
    if not isinstance(runtime_entrypoint, str) or not runtime_entrypoint:
        raise SystemExit(f"lowered IR object {object_id!r} is missing runtime_entrypoint")
    if object_kind in FORBIDDEN_RUNTIME_OBJECT_KINDS:
        raise SystemExit(
            f"lowered IR object {object_id!r} materializes runtime-owned object kind {object_kind!r}"
        )
    expected_entrypoint = RUNTIME_ENTRYPOINT_BY_KIND.get(object_kind)
    if expected_entrypoint is None:
        raise SystemExit(
            f"lowered IR object {object_id!r} has unknown object kind {object_kind!r}"
        )
    if object_kind not in CURRENT_SUPPORTED_CORE_OBJECT_KINDS:
        raise SystemExit(
            f"lowered IR object {object_id!r} kind {object_kind!r} is known but not admitted by the current executable lowering/runtime handoff slice"
        )
    if runtime_entrypoint in FORBIDDEN_RUNTIME_ENTRYPOINTS:
        raise SystemExit(
            f"lowered IR object {object_id!r} materializes runtime-owned entrypoint {runtime_entrypoint!r}"
        )
    if runtime_entrypoint != expected_entrypoint:
        raise SystemExit(
            f"lowered IR object {object_id!r} kind {object_kind!r} must use {expected_entrypoint!r}, got {runtime_entrypoint!r}"
        )
    if runtime_entrypoint not in CURRENT_SUPPORTED_RUNTIME_ENTRYPOINTS:
        raise SystemExit(
            f"lowered IR object {object_id!r} runtime entrypoint {runtime_entrypoint!r} is known but not admitted by the current executable lowering/runtime handoff slice"
        )
    validate_lowered_ir_entrypoint_refs(obj, object_id, object_kind, runtime_entrypoint)


def lowered_ir_required_entrypoint_ref_keys(
    object_kind: str,
    runtime_entrypoint: str,
) -> list[str]:
    if object_kind == "fact" and runtime_entrypoint == "fact_record":
        return ["fact", "schema"]
    if object_kind == "event" and runtime_entrypoint == "event_record":
        return ["event"]
    if object_kind == "signal_source" and runtime_entrypoint == "signal_source_template":
        return ["event"]
    if object_kind == "schedule" and runtime_entrypoint == "schedule_template":
        return ["schedule"]
    if object_kind == "rule" and runtime_entrypoint == "rule_template":
        return ["rule", "fact", "graph"]
    if object_kind == "dependency" and runtime_entrypoint == "effect_dependency_template":
        return ["upstream_effect", "predicate", "downstream_effect"]
    if object_kind == "projection" and runtime_entrypoint == "event_projection":
        return ["event", "fact"]
    if object_kind == "assertion" and runtime_entrypoint == "assertion_check":
        return ["assertion"]
    if object_kind == "diagnostic" and runtime_entrypoint == "diagnostic_record":
        return ["rule"]
    return []


def validate_lowered_ir_entrypoint_refs(
    obj: dict[str, Any],
    object_id: str,
    object_kind: str,
    runtime_entrypoint: str,
) -> None:
    required_keys = lowered_ir_required_entrypoint_ref_keys(
        object_kind,
        runtime_entrypoint,
    )
    if not required_keys:
        return
    refs = obj.get("entrypoint_refs")
    if not isinstance(refs, dict):
        raise SystemExit(
            f"{object_kind} lowered IR object {object_id!r} is missing entrypoint_refs"
        )
    for key in required_keys:
        value = refs.get(key)
        if not isinstance(value, str) or not value:
            raise SystemExit(
                f"{object_kind} lowered IR object {object_id!r} is missing {key}"
            )
    if runtime_entrypoint == "effect_dependency_template":
        predicate = refs.get("predicate")
        if predicate not in {"succeeds", "fails", "completes"}:
            raise SystemExit(
                f"dependency lowered IR object {object_id!r} has unknown predicate {predicate!r}"
            )


def expect_lowered_ir_entrypoint_ref(
    obj: dict[str, Any],
    object_id: str,
    key: str,
    expected: str,
) -> None:
    refs = obj.get("entrypoint_refs")
    if not isinstance(refs, dict):
        return
    actual = refs.get(key)
    if actual != expected:
        raise SystemExit(
            f"lowered IR object {object_id!r} entrypoint ref {key!r} "
            f"expected {expected!r}, got {actual!r}"
        )


def validate_lowered_ir_entrypoint_ref_values(
    obj: dict[str, Any],
    graph_nodes_by_id: dict[str, dict[str, Any]],
    graph_dependencies_by_ref: dict[str, dict[str, Any]],
) -> None:
    object_id = obj.get("object_id")
    object_kind = obj.get("object_kind")
    runtime_entrypoint = obj.get("runtime_entrypoint")
    owner_kind = obj.get("owner_kind")
    owner_ref = obj.get("owner_ref")
    if not isinstance(object_id, str) or not isinstance(owner_ref, str):
        return

    if (
        object_kind == "schedule"
        and runtime_entrypoint == "schedule_template"
        and owner_kind == "node"
    ):
        expect_lowered_ir_entrypoint_ref(obj, object_id, "schedule", owner_ref)
        return

    if (
        object_kind == "signal_source"
        and runtime_entrypoint == "signal_source_template"
        and owner_kind == "node"
    ):
        # A `source … { observe; emit <signal> }` block admits a signal whose name
        # is decoupled from the source node's own name, so only the
        # signal-declaration form pins the event to the owning node id.
        if not owner_ref.startswith("source:"):
            event_ref = owner_ref.removeprefix("signal_source:")
            expect_lowered_ir_entrypoint_ref(obj, object_id, "event", event_ref)
        return

    if (
        object_kind == "clock_source"
        and runtime_entrypoint == "clock_source_template"
        and owner_kind == "node"
    ):
        # Clock sources admit a signal whose name is decoupled from the source name.
        return

    if (
        object_kind == "assertion"
        and runtime_entrypoint == "assertion_check"
        and owner_kind == "node"
    ):
        assertion_ref = owner_ref.removeprefix("assertion:")
        expect_lowered_ir_entrypoint_ref(obj, object_id, "assertion", assertion_ref)
        return

    if (
        object_kind == "rule"
        and runtime_entrypoint == "rule_template"
        and owner_kind == "node"
    ):
        node = graph_nodes_by_id.get(owner_ref)
        metadata = node.get("metadata") if isinstance(node, dict) else None
        rule_name = metadata.get("rule_name") if isinstance(metadata, dict) else None
        if isinstance(rule_name, str) and rule_name:
            expect_lowered_ir_entrypoint_ref(obj, object_id, "rule", rule_name)
        if owner_ref.startswith("rule:"):
            rule_ref = owner_ref.removeprefix("rule:")
            expect_lowered_ir_entrypoint_ref(
                obj,
                object_id,
                "graph",
                f"{rule_ref}:graph",
            )
        return

    if (
        object_kind == "fact"
        and runtime_entrypoint == "fact_record"
        and owner_kind == "node"
    ):
        prefix = f"core:fact:{owner_ref}:"
        if not object_id.startswith(prefix):
            raise SystemExit(
                f"fact lowered IR object {object_id!r} does not encode owner node {owner_ref!r}"
            )
        fact_ref = object_id.removeprefix(prefix)
        expect_lowered_ir_entrypoint_ref(obj, object_id, "fact", fact_ref)
        expect_lowered_ir_entrypoint_ref(
            obj,
            object_id,
            "schema",
            fact_ref.removeprefix("schema:"),
        )
        return

    if (
        object_kind == "dependency"
        and runtime_entrypoint == "effect_dependency_template"
        and owner_kind == "dependency"
    ):
        dependency = graph_dependencies_by_ref.get(owner_ref)
        if not isinstance(dependency, dict):
            return
        expected = {
            "upstream_effect": dependency.get("upstream_node_id"),
            "predicate": dependency.get("predicate"),
            "downstream_effect": dependency.get("downstream_node_id"),
        }
        for key, value in expected.items():
            if isinstance(value, str) and value:
                expect_lowered_ir_entrypoint_ref(obj, object_id, key, value)


def validate_lowered_ir_inventory(graph: dict[str, Any], lowered: dict[str, Any]) -> None:
    graph_node_ids = {
        node.get("node_id")
        for node in graph.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("node_id"), str)
    }
    graph_nodes_by_id = {
        node["node_id"]: node
        for node in graph.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("node_id"), str)
    }
    graph_edge_refs = {
        edge_ref(edge["required_port_id"], edge["provided_port_id"])
        for edge in graph.get("edges", [])
        if (
            isinstance(edge, dict)
            and isinstance(edge.get("required_port_id"), str)
            and isinstance(edge.get("provided_port_id"), str)
        )
    }
    graph_dependency_refs = {
        dependency.get("dependency_ref")
        for dependency in graph.get("effect_dependencies", [])
        if isinstance(dependency, dict)
        and isinstance(dependency.get("dependency_ref"), str)
    }
    graph_dependencies_by_ref = {
        dependency["dependency_ref"]: dependency
        for dependency in graph.get("effect_dependencies", [])
        if isinstance(dependency, dict)
        and isinstance(dependency.get("dependency_ref"), str)
    }

    node_lowering_refs: list[str] = []
    edge_lowering_refs: list[str] = []
    dependency_lowering_refs: list[str] = []
    produced_owners: dict[str, list[str]] = {}

    def record_owner(object_id: str, owner: str) -> None:
        if object_id:
            produced_owners.setdefault(object_id, []).append(owner)

    for lowering in lowered.get("node_lowerings", []):
        if not isinstance(lowering, dict):
            raise SystemExit("lowered IR report node_lowerings entries must be objects")
        node_id = lowering.get("node_id")
        if not isinstance(node_id, str) or not node_id:
            raise SystemExit("lowered IR report node lowering is missing node_id")
        node_lowering_refs.append(node_id)
        if node_id not in graph_node_ids:
            raise SystemExit(
                f"lowered IR report node lowering references unknown graph node {node_id!r}"
            )
        owner = lowered_ir_owner_token("node", node_id)
        for object_id in string_array(lowering, "produced_core_object_refs"):
            record_owner(object_id, owner)

    for lowering in lowered.get("edge_lowerings", []):
        if not isinstance(lowering, dict):
            raise SystemExit("lowered IR report edge_lowerings entries must be objects")
        required_port_id = lowering.get("required_port_id")
        provided_port_id = lowering.get("provided_port_id")
        if not isinstance(required_port_id, str) or not isinstance(provided_port_id, str):
            raise SystemExit(
                "lowered IR report edge lowering is missing required/provided port IDs"
            )
        ref = edge_ref(required_port_id, provided_port_id)
        edge_lowering_refs.append(ref)
        if ref not in graph_edge_refs:
            raise SystemExit(
                f"lowered IR report edge lowering references unknown graph edge {ref!r}"
            )
        owner = lowered_ir_owner_token("edge", ref)
        for object_id in string_array(lowering, "produced_core_object_refs"):
            record_owner(object_id, owner)

    for lowering in lowered.get("dependency_lowerings", []):
        if not isinstance(lowering, dict):
            raise SystemExit(
                "lowered IR report dependency_lowerings entries must be objects"
            )
        dependency_ref = lowering.get("dependency_ref")
        if not isinstance(dependency_ref, str) or not dependency_ref:
            raise SystemExit(
                "lowered IR report dependency lowering is missing dependency_ref"
            )
        dependency_lowering_refs.append(dependency_ref)
        if dependency_ref not in graph_dependency_refs:
            raise SystemExit(
                "lowered IR report dependency lowering references unknown graph "
                f"dependency {dependency_ref!r}"
            )
        owner = lowered_ir_owner_token("dependency", dependency_ref)
        for object_id in string_array(lowering, "produced_core_object_refs"):
            record_owner(object_id, owner)

    validate_unique_refs(node_lowering_refs, "node lowering refs")
    validate_unique_refs(edge_lowering_refs, "edge lowering refs")
    validate_unique_refs(dependency_lowering_refs, "dependency lowering refs")

    missing_nodes = sorted(graph_node_ids - set(node_lowering_refs))
    missing_edges = sorted(graph_edge_refs - set(edge_lowering_refs))
    missing_dependencies = sorted(graph_dependency_refs - set(dependency_lowering_refs))
    if missing_nodes:
        raise SystemExit(
            "lowered IR report is missing graph node lowering(s): "
            + ", ".join(missing_nodes[:8])
        )
    if missing_edges:
        raise SystemExit(
            "lowered IR report is missing graph edge lowering(s): "
            + ", ".join(missing_edges[:8])
        )
    if missing_dependencies:
        raise SystemExit(
            "lowered IR report is missing graph dependency lowering(s): "
            + ", ".join(missing_dependencies[:8])
        )

    core_objects = [
        obj for obj in lowered.get("core_objects", []) if isinstance(obj, dict)
    ]
    core_object_refs = [
        obj.get("object_id")
        for obj in core_objects
        if isinstance(obj.get("object_id"), str)
    ]
    validate_unique_refs(core_object_refs, "core object IDs")
    core_object_ids = set(core_object_refs)

    for object_id, owners in produced_owners.items():
        if object_id not in core_object_ids:
            raise SystemExit(
                f"lowered IR report lowering references missing core object {object_id!r}"
            )
        if len(owners) != 1:
            raise SystemExit(
                f"lowered IR report core object {object_id!r} has multiple lowering owners: "
                + ", ".join(owners)
            )

    for obj in core_objects:
        validate_lowered_ir_core_object_kind_and_entrypoint(obj)
        object_id = obj["object_id"]
        owner_kind = obj.get("owner_kind")
        owner_ref = obj.get("owner_ref")
        if not isinstance(owner_kind, str) or not isinstance(owner_ref, str) or not owner_ref:
            raise SystemExit(
                f"lowered IR report core object {object_id!r} is missing owner kind/ref"
            )
        if owner_kind == "node" and owner_ref not in graph_node_ids:
            raise SystemExit(
                f"lowered IR report core object {object_id!r} references unknown owner node {owner_ref!r}"
            )
        if owner_kind == "edge" and owner_ref not in graph_edge_refs:
            raise SystemExit(
                f"lowered IR report core object {object_id!r} references unknown owner edge {owner_ref!r}"
            )
        if owner_kind == "dependency" and owner_ref not in graph_dependency_refs:
            raise SystemExit(
                "lowered IR report core object "
                f"{object_id!r} references unknown owner dependency {owner_ref!r}"
            )
        owner = lowered_ir_owner_token(owner_kind, owner_ref)
        produced = produced_owners.get(object_id, [])
        if not produced:
            raise SystemExit(
                f"lowered IR report core object {object_id!r} is not produced by any lowering"
            )
        if produced != [owner]:
            raise SystemExit(
                f"lowered IR report core object {object_id!r} declares owner {owner!r} "
                f"but lowering inventory produced {produced[0]!r}"
            )
        validate_lowered_ir_entrypoint_ref_values(
            obj,
            graph_nodes_by_id,
            graph_dependencies_by_ref,
        )


def edge_preservation_refs(graph_id: str, ref: str, lowering: dict[str, Any]) -> list[str]:
    refs = [graph_id, ref]
    for key in ["required_port_id", "provided_port_id", "core_relation_ref"]:
        refs.extend(optional_string_ref(lowering, key))
    for key in [
        "produced_core_object_refs",
        "preserved_type_refs",
        "preserved_resource_refs",
        "preserved_capability_refs",
        "preserved_version_refs",
        "preserved_span_refs",
        "preserved_cardinality_refs",
        "preserved_provenance_refs",
    ]:
        refs.extend(string_array(lowering, key))
    return refs


def edge_preservation_component_refs(
    graph_id: str,
    ref: str,
    lowering: dict[str, Any],
    field: str,
) -> list[str]:
    refs = [graph_id, ref]
    if field in {"required_port_id", "provided_port_id", "core_relation_ref"}:
        refs.extend(optional_string_ref(lowering, field))
    else:
        refs.extend(string_array(lowering, field))
    return refs


def dependency_preservation_refs(
    graph_id: str,
    dependency_ref: str,
    lowering: dict[str, Any],
) -> list[str]:
    refs = [graph_id, dependency_ref]
    refs.extend(optional_string_ref(lowering, "preserved_predicate"))
    for key in [
        "produced_core_object_refs",
        "preserved_effect_refs",
        "preserved_span_refs",
        "preserved_provenance_refs",
    ]:
        refs.extend(string_array(lowering, key))
    return refs


def dependency_preservation_component_refs(
    graph_id: str,
    dependency_ref: str,
    lowering: dict[str, Any],
    field: str,
) -> list[str]:
    refs = [graph_id, dependency_ref]
    if field == "preserved_predicate":
        refs.extend(optional_string_ref(lowering, field))
    else:
        refs.extend(string_array(lowering, field))
    return refs


def validate_lowered_ir_trace(graph: dict[str, Any], lowered: dict[str, Any]) -> None:
    validate_lowered_ir_inventory(graph, lowered)
    predicates = derived_fact_predicates(
        lowered,
        "lowered IR report",
        "lowered_ir_validator",
    )
    graph_id = lowered.get("graph_id", "unknown")
    graph_nodes_by_id = {
        node.get("node_id"): node
        for node in graph.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("node_id"), str)
    }
    core_objects_by_id = {
        obj.get("object_id"): obj
        for obj in lowered.get("core_objects", [])
        if isinstance(obj, dict) and isinstance(obj.get("object_id"), str)
    }
    required: dict[str, set[str]] = {}
    coverage_refs = [graph_id]
    owner_refs = [graph_id]
    runtime_boundary_refs = [graph_id]
    determinism_refs = graph_determinism_refs(lowered)
    report_complete_refs = graph_report_root_refs(lowered)
    no_runtime_input_refs = [lowered_report_field_ref(lowered, "graph_id")]
    node_lowering_refs: list[str] = []
    edge_lowering_refs: list[str] = []
    dependency_lowering_refs: list[str] = []
    core_object_refs: list[str] = []

    for lowering in lowered.get("node_lowerings", []):
        node_id = lowering.get("node_id")
        if not isinstance(node_id, str) or not node_id:
            continue
        node_lowering_refs.append(node_id)
        report_complete_refs.append(lowered_inventory_ref("node_lowering", node_id))
        refs = [graph_id, node_id, *string_array(lowering, "produced_core_object_refs")]
        require_predicate(
            required,
            f"lowered_ir.validator.node.lowered:{node_id}",
            refs,
        )
        require_predicate(
            required,
            f"lowered_ir.validator.node.preservation:{node_id}",
            node_preservation_refs(graph_id, node_id, lowering),
        )
        for fact_field, report_field in NODE_PRESERVATION_COMPONENT_FIELDS:
            require_predicate(
                required,
                f"lowered_ir.validator.node.preservation.{fact_field}:{node_id}",
                node_preservation_component_refs(
                    graph_id,
                    node_id,
                    lowering,
                    report_field,
                ),
            )
        output_refs = node_output_compat_refs(
            graph_id,
            node_id,
            lowering,
            graph_nodes_by_id.get(node_id),
            core_objects_by_id,
        )
        require_predicate(
            required,
            f"lowered_ir.validator.node.output_compat:{node_id}",
            output_refs,
        )
        for fact_field in NODE_OUTPUT_COMPAT_COMPONENT_FIELDS:
            require_predicate(
                required,
                f"lowered_ir.validator.node.output_compat.{fact_field}:{node_id}",
                node_output_compat_component_refs(
                    graph_id,
                    node_id,
                    lowering,
                    graph_nodes_by_id.get(node_id),
                    core_objects_by_id,
                    fact_field,
                ),
            )
        validate_node_output_compatibility(
            node_id,
            lowering,
            graph_nodes_by_id,
            core_objects_by_id,
        )
        lowering_class = lowering.get("lowering_class")
        if isinstance(lowering_class, str) and lowering_class:
            require_predicate(
                required,
                f"lowered_ir.validator.node.lifecycle_inputs:{node_id}:{lowering_class}",
                node_lifecycle_input_refs(
                    graph_id,
                    node_id,
                    lowering,
                    graph_nodes_by_id.get(node_id),
                    core_objects_by_id,
                ),
            )
            for fact_field in NODE_LIFECYCLE_INPUT_COMPONENT_FIELDS:
                require_predicate(
                    required,
                    f"lowered_ir.validator.node.lifecycle_inputs.{fact_field}:{node_id}:{lowering_class}",
                    node_lifecycle_input_component_refs(
                        graph_id,
                        node_id,
                        lowering,
                        graph_nodes_by_id.get(node_id),
                        core_objects_by_id,
                        fact_field,
                    ),
                )
        coverage_refs.append(node_id)

    for lowering in lowered.get("edge_lowerings", []):
        required_port_id = lowering.get("required_port_id")
        provided_port_id = lowering.get("provided_port_id")
        if isinstance(required_port_id, str) and isinstance(provided_port_id, str):
            ref = edge_ref(required_port_id, provided_port_id)
            edge_lowering_refs.append(ref)
            report_complete_refs.append(lowered_inventory_ref("edge_lowering", ref))
            require_predicate(
                required,
                f"lowered_ir.validator.edge.lowered:{ref}",
                [
                    graph_id,
                    ref,
                    required_port_id,
                    provided_port_id,
                    *string_array(lowering, "produced_core_object_refs"),
                ],
            )
            require_predicate(
                required,
                f"lowered_ir.validator.edge.preservation:{ref}",
                edge_preservation_refs(graph_id, ref, lowering),
            )
            for fact_field, report_field in EDGE_PRESERVATION_COMPONENT_FIELDS:
                require_predicate(
                    required,
                    f"lowered_ir.validator.edge.preservation.{fact_field}:{ref}",
                    edge_preservation_component_refs(
                        graph_id,
                        ref,
                        lowering,
                        report_field,
                    ),
                )
            coverage_refs.append(ref)

    for lowering in lowered.get("dependency_lowerings", []):
        dependency_ref = lowering.get("dependency_ref")
        if isinstance(dependency_ref, str) and dependency_ref:
            dependency_lowering_refs.append(dependency_ref)
            report_complete_refs.append(
                lowered_inventory_ref("dependency_lowering", dependency_ref)
            )
            require_predicate(
                required,
                f"lowered_ir.validator.dependency.lowered:{dependency_ref}",
                [
                    graph_id,
                    dependency_ref,
                    *string_array(lowering, "produced_core_object_refs"),
                ],
            )
            require_predicate(
                required,
                f"lowered_ir.validator.dependency.preservation:{dependency_ref}",
                dependency_preservation_refs(graph_id, dependency_ref, lowering),
            )
            for fact_field, report_field in DEPENDENCY_PRESERVATION_COMPONENT_FIELDS:
                require_predicate(
                    required,
                    f"lowered_ir.validator.dependency.preservation.{fact_field}:{dependency_ref}",
                    dependency_preservation_component_refs(
                        graph_id,
                        dependency_ref,
                        lowering,
                        report_field,
                    ),
                )
            coverage_refs.append(dependency_ref)

    for obj in lowered.get("core_objects", []):
        object_id = obj.get("object_id")
        if not isinstance(object_id, str) or not object_id:
            continue
        core_object_refs.append(object_id)
        object_kind = obj.get("object_kind", "unknown")
        runtime_entrypoint = obj.get("runtime_entrypoint", "unknown")
        owner_kind = obj.get("owner_kind", "unknown")
        owner_ref = obj.get("owner_ref", "unknown")
        report_complete_refs.append(lowered_inventory_ref("core_object", object_id))
        no_runtime_input_refs.append(
            lowered_runtime_object_ref(object_id, object_kind, runtime_entrypoint)
        )
        require_predicate(
            required,
            "lowered_ir.validator.core_object.entrypoint:"
            f"{object_id}:{object_kind}:{runtime_entrypoint}",
            core_object_entrypoint_refs(
                graph_id,
                object_id,
                obj,
                object_kind,
                runtime_entrypoint,
            ),
        )
        require_predicate(
            required,
            f"lowered_ir.validator.core_object.owner:{object_id}:{owner_kind}:{owner_ref}",
            [graph_id, object_id, owner_kind, owner_ref],
        )
        coverage_refs.append(object_id)
        owner_refs.extend([object_id, owner_kind, owner_ref])
        runtime_boundary_refs.extend([object_id, object_kind, runtime_entrypoint])

    validate_unique_refs(node_lowering_refs, "node lowering refs")
    validate_unique_refs(edge_lowering_refs, "edge lowering refs")
    validate_unique_refs(dependency_lowering_refs, "dependency lowering refs")
    validate_unique_refs(core_object_refs, "core object IDs")
    require_predicate(
        required,
        f"lowered_ir.validator.graph.node_lowerings_unique:{graph_id}",
        node_lowering_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.edge_lowerings_unique:{graph_id}",
        edge_lowering_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.dependency_lowerings_unique:{graph_id}",
        dependency_lowering_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.core_object_ids_unique:{graph_id}",
        core_object_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.coverage:{graph_id}",
        coverage_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.deterministic:{graph_id}",
        determinism_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.report_complete:{graph_id}",
        report_complete_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.owner_unique:{graph_id}",
        owner_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.no_runtime_inputs:{graph_id}",
        no_runtime_input_refs,
    )
    require_predicate(
        required,
        f"lowered_ir.validator.graph.runtime_boundary:{graph_id}",
        runtime_boundary_refs,
    )

    validate_required_predicates(predicates, required, "lowered IR report")


def maude_lowering_class(symbols: SymbolTable, lowering_class: str) -> str:
    return LOWERING_CLASS.get(lowering_class) or symbols.symbol(
        "LoweringClass", "lowering", lowering_class
    )


def maude_construct_family(symbols: SymbolTable, construct_family: str) -> str:
    return CONSTRUCT_FAMILY.get(construct_family) or symbols.symbol(
        "ConstructFamily", "family", construct_family
    )


def maude_core_kind(symbols: SymbolTable, object_kind: str) -> str:
    return CORE_KIND.get(object_kind) or symbols.symbol(
        "CoreObjectKind", "coreKind", object_kind
    )


def maude_runtime_entrypoint_kind(
    symbols: SymbolTable,
    runtime_entrypoint: str,
) -> str:
    return RUNTIME_ENTRYPOINT_KIND.get(runtime_entrypoint) or symbols.symbol(
        "RuntimeEntrypointKind", "entrypoint", runtime_entrypoint
    )


def maude_runtime_entrypoint_fact(
    symbols: SymbolTable,
    obj: dict[str, Any],
    object_symbol: str,
) -> str:
    object_id = obj["object_id"]
    runtime_entrypoint = obj["runtime_entrypoint"]
    if runtime_entrypoint == "fact_record":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"fact lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        fact = refs.get("fact")
        if not isinstance(fact, str) or not fact:
            raise SystemExit(f"fact lowered IR object {object_id!r} is missing fact")
        fact_symbol = symbols.symbol("FactId", "fact", fact)
        return f"factEntrypoint({object_symbol}, {fact_symbol})"
    if runtime_entrypoint == "event_record":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"event lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        event = refs.get("event")
        if not isinstance(event, str) or not event:
            raise SystemExit(f"event lowered IR object {object_id!r} is missing event")
        event_symbol = symbols.symbol("EventId", "event", event)
        return f"eventEntrypoint({object_symbol}, {event_symbol})"
    if runtime_entrypoint == "effect_graph_template":
        effect_symbol = symbols.symbol("EffectId", "effect", object_id)
        return f"effectEntrypoint({object_symbol}, {effect_symbol})"
    if runtime_entrypoint == "signal_source_template":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"event source lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        event = refs.get("event")
        if not isinstance(event, str) or not event:
            raise SystemExit(
                f"event source lowered IR object {object_id!r} is missing event"
            )
        event_symbol = symbols.symbol("EventId", "event", event)
        return f"eventSourceEntrypoint({object_symbol}, {event_symbol})"
    if runtime_entrypoint == "schedule_template":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"schedule lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        schedule = refs.get("schedule")
        if not isinstance(schedule, str) or not schedule:
            raise SystemExit(
                f"schedule lowered IR object {object_id!r} is missing schedule"
            )
        schedule_symbol = symbols.symbol("EventId", "schedule", schedule)
        return f"scheduleEntrypoint({object_symbol}, {schedule_symbol})"
    if runtime_entrypoint == "rule_template":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"rule lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        rule = refs.get("rule")
        fact = refs.get("fact")
        graph = refs.get("graph")
        if not isinstance(rule, str) or not rule:
            raise SystemExit(f"rule lowered IR object {object_id!r} is missing rule")
        if not isinstance(fact, str) or not fact:
            raise SystemExit(f"rule lowered IR object {object_id!r} is missing fact")
        if not isinstance(graph, str) or not graph:
            raise SystemExit(f"rule lowered IR object {object_id!r} is missing graph")
        rule_symbol = symbols.symbol("RuleId", "rule", rule)
        fact_symbol = symbols.symbol("FactId", "fact", fact)
        graph_symbol = symbols.symbol("GraphId", "graph", graph)
        return (
            f"ruleEntrypoint({object_symbol}, {rule_symbol}, "
            f"{fact_symbol}, {graph_symbol})"
        )
    if runtime_entrypoint == "effect_dependency_template":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"dependency lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        upstream = refs.get("upstream_effect")
        predicate = refs.get("predicate")
        downstream = refs.get("downstream_effect")
        if not isinstance(upstream, str) or not upstream:
            raise SystemExit(
                f"dependency lowered IR object {object_id!r} is missing upstream_effect"
            )
        if not isinstance(downstream, str) or not downstream:
            raise SystemExit(
                f"dependency lowered IR object {object_id!r} is missing downstream_effect"
            )
        if predicate not in {"succeeds", "fails", "completes"}:
            raise SystemExit(
                f"dependency lowered IR object {object_id!r} has unknown predicate {predicate!r}"
            )
        upstream_symbol = symbols.symbol("EffectId", "effect", upstream)
        downstream_symbol = symbols.symbol("EffectId", "effect", downstream)
        return (
            f"dependencyEntrypoint({object_symbol}, {upstream_symbol}, "
            f"{predicate}, {downstream_symbol})"
        )
    if runtime_entrypoint == "event_projection":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"projection lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        event = refs.get("event")
        fact = refs.get("fact")
        if not isinstance(event, str) or not event:
            raise SystemExit(
                f"projection lowered IR object {object_id!r} is missing event"
            )
        if not isinstance(fact, str) or not fact:
            raise SystemExit(
                f"projection lowered IR object {object_id!r} is missing fact"
            )
        event_symbol = symbols.symbol("EventId", "event", event)
        fact_symbol = symbols.symbol("FactId", "fact", fact)
        return f"projectionEntrypoint({object_symbol}, {event_symbol}, {fact_symbol})"
    if runtime_entrypoint == "assertion_check":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"assertion lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        assertion = refs.get("assertion")
        if not isinstance(assertion, str) or not assertion:
            raise SystemExit(
                f"assertion lowered IR object {object_id!r} is missing assertion"
            )
        assertion_symbol = symbols.symbol("AssertionId", "assertion", assertion)
        return f"assertionEntrypoint({object_symbol}, {assertion_symbol})"
    if runtime_entrypoint == "diagnostic_record":
        refs = obj.get("entrypoint_refs")
        if not isinstance(refs, dict):
            raise SystemExit(
                f"diagnostic lowered IR object {object_id!r} is missing entrypoint_refs"
            )
        rule = refs.get("rule")
        if not isinstance(rule, str) or not rule:
            raise SystemExit(
                f"diagnostic lowered IR object {object_id!r} is missing rule"
            )
        rule_symbol = symbols.symbol("RuleId", "rule", rule)
        return f"diagnosticEntrypoint({object_symbol}, {rule_symbol})"
    raise SystemExit(
        f"generated runtime handoff bridge does not yet support runtime entrypoint {runtime_entrypoint!r}"
    )


def runtime_boundary_facts_from_inventory(
    graph_symbol: str,
    core_objects: list[dict[str, Any]],
) -> list[str]:
    for obj in core_objects:
        object_id = obj["object_id"]
        object_kind = obj["object_kind"]
        runtime_entrypoint = obj["runtime_entrypoint"]
        if object_kind in FORBIDDEN_RUNTIME_OBJECT_KINDS:
            raise SystemExit(
                f"lowered IR object {object_id!r} materializes runtime-owned object kind {object_kind!r}"
            )
        expected_entrypoint = RUNTIME_ENTRYPOINT_BY_KIND.get(object_kind)
        if expected_entrypoint is None:
            raise SystemExit(
                f"lowered IR object {object_id!r} has unknown object kind {object_kind!r}"
            )
        if object_kind not in CURRENT_SUPPORTED_CORE_OBJECT_KINDS:
            raise SystemExit(
                f"lowered IR object {object_id!r} kind {object_kind!r} is known but not admitted by the current executable lowering/runtime handoff slice"
            )
        if runtime_entrypoint in FORBIDDEN_RUNTIME_ENTRYPOINTS:
            raise SystemExit(
                f"lowered IR object {object_id!r} materializes runtime-owned entrypoint {runtime_entrypoint!r}"
            )
        if runtime_entrypoint != expected_entrypoint:
            raise SystemExit(
                f"lowered IR object {object_id!r} kind {object_kind!r} must use {expected_entrypoint!r}, got {runtime_entrypoint!r}"
            )
        if runtime_entrypoint not in CURRENT_SUPPORTED_RUNTIME_ENTRYPOINTS:
            raise SystemExit(
                f"lowered IR object {object_id!r} runtime entrypoint {runtime_entrypoint!r} is known but not admitted by the current executable lowering/runtime handoff slice"
            )
    return [
        f"noLoweredRunMaterialization({graph_symbol})",
        f"noLoweredClaimMaterialization({graph_symbol})",
        f"noLoweredTerminalMaterialization({graph_symbol})",
        f"noLoweredCancellationMaterialization({graph_symbol})",
        f"noLoweredRetryLeaseMaterialization({graph_symbol})",
        f"providerBoundaryRuntimeOwned({graph_symbol})",
    ]


def maude_edge_ref_list(edge_symbols: list[tuple[str, str, str, str]]) -> str:
    result = "noEdges"
    for required_node, required_port, provider_node, provided_port in reversed(edge_symbols):
        result = (
            f"edgeCons(edgeId({required_node}, {required_port}, "
            f"{provider_node}, {provided_port}), {result})"
        )
    return result


def maude_node_needs_edges(
    node_symbol: str,
    edge_symbols: list[tuple[str, str, str, str]],
) -> str:
    return f"nodeNeedsEdges({node_symbol}, {maude_edge_ref_list(edge_symbols)})"


def maude_node_core_objects(node_symbol: str, object_symbols: list[str]) -> str:
    return (
        f"nodeCoreObjects({node_symbol}, "
        f"{maude_core_object_list(object_symbols)})"
    )


def maude_node_class_output(
    symbols: SymbolTable,
    node_symbol: str,
    lowering_class_symbol: str,
    owned_objects: list[dict[str, Any]],
    object_symbols: dict[str, str],
) -> str:
    object_refs = [
        (
            object_symbols[obj["object_id"]],
            maude_core_kind(symbols, obj["object_kind"]),
            maude_runtime_entrypoint_kind(symbols, obj["runtime_entrypoint"]),
        )
        for obj in owned_objects
    ]
    return (
        f"nodeClassOutput({node_symbol}, {lowering_class_symbol}, "
        f"{maude_node_class_output_list(object_refs)})"
    )


def lowering_class_authority_facts(
    lowering: dict[str, Any],
    lowering_symbol: str,
) -> list[str]:
    authority_profile = lowering.get("authority_profile")
    if authority_profile == "none":
        return [f"classNoAuthorityNeeded({lowering_symbol})"]
    if authority_profile == "capability_scoped":
        return [
            f"classCapabilityScoped({lowering_symbol})",
            f"classOutputBoundaryValidated({lowering_symbol})",
        ]
    if authority_profile == "event_admission":
        return [
            f"classEventPayloadTyped({lowering_symbol})",
            f"classEventAdmissionOwned({lowering_symbol})",
        ]
    if authority_profile == "projection_source":
        return [f"classProjectionSourceTyped({lowering_symbol})"]
    raise SystemExit(
        "generated lowered IR bridge has unsupported lifecycle authority "
        f"profile {authority_profile!r} for lowering class {lowering.get('id')!r}"
    )


def lowering_class_profile_facts(
    symbols: SymbolTable,
    node: dict[str, Any],
    lowering: dict[str, Any],
    lowering_symbol: str,
    family_symbol: str,
    owned_objects: list[dict[str, Any]],
) -> list[str]:
    lowering_class = lowering.get("id")
    node_id = node.get("node_id", "unknown")
    construct_family = node.get("construct_family")
    compatible_families = set(string_array(lowering, "compatible_families"))
    if construct_family not in compatible_families:
        expected = ", ".join(sorted(compatible_families))
        raise SystemExit(
            f"lowered IR bridge node {node_id!r} lowering class "
            f"{lowering_class!r} is incompatible with construct family "
            f"{construct_family!r}; expected one of {expected}"
        )
    lifecycle_profile = node.get("lifecycle_profile")
    lifecycle_profiles = set(string_array(lowering, "lifecycle_profiles"))
    if lifecycle_profile not in lifecycle_profiles:
        expected = ", ".join(sorted(lifecycle_profiles))
        raise SystemExit(
            f"lowered IR bridge node {node_id!r} lowering class "
            f"{lowering_class!r} requires lifecycle profile {expected}, "
            f"got {lifecycle_profile!r}"
        )
    facts = [
        f"classRegistered({lowering_symbol})",
        f"classAllowsFamily({lowering_symbol}, {family_symbol})",
    ]
    for guarantee in string_array(lowering, "static_guarantees"):
        predicate = STATIC_GUARANTEE_FACTS.get(guarantee)
        if predicate is None:
            raise SystemExit(
                "generated lowered IR bridge has unsupported static guarantee "
                f"{guarantee!r} for lowering class {lowering_class!r}"
            )
        facts.append(f"{predicate}({lowering_symbol})")
    facts.extend(lowering_class_authority_facts(lowering, lowering_symbol))
    if not owned_objects:
        facts.extend([
            f"classAllowsNoOutput({lowering_symbol})",
            f"classCoreOutputs({lowering_symbol}, noClassOutputs)",
        ])
        return facts
    outputs = [
        (
            maude_core_kind(symbols, obj["object_kind"]),
            maude_runtime_entrypoint_kind(symbols, obj["runtime_entrypoint"]),
        )
        for obj in owned_objects
    ]
    for kind_symbol, entrypoint_symbol in outputs:
        facts.extend([
            f"classAllowsOutput({lowering_symbol}, {kind_symbol}, {entrypoint_symbol})",
            f"entrypointMatchesObjectKind({kind_symbol}, {entrypoint_symbol})",
        ])
    facts.append(
        f"classCoreOutputs({lowering_symbol}, {maude_class_output_list(outputs)})"
    )
    return facts


def maude_edge_core_objects(
    node_symbol: str,
    required_port_symbol: str,
    provider_node_symbol: str,
    provided_port_symbol: str,
    object_symbols: list[str],
) -> str:
    return (
        f"edgeCoreObjects({node_symbol}, {required_port_symbol}, "
        f"{provider_node_symbol}, {provided_port_symbol}, "
        f"{maude_core_object_list(object_symbols)})"
    )


def maude_dependency_core_objects(
    dependency_symbol: str,
    object_symbols: list[str],
) -> str:
    return (
        f"dependencyCoreObjects({dependency_symbol}, "
        f"{maude_core_object_list(object_symbols)})"
    )


def maude_core_object_list(object_symbols: list[str]) -> str:
    result = "noCoreObjects"
    for object_symbol in reversed(object_symbols):
        result = f"coreObjectCons({object_symbol}, {result})"
    return result


def maude_class_output_list(output_refs: list[tuple[str, str]]) -> str:
    result = "noClassOutputs"
    for kind_symbol, entrypoint_symbol in reversed(output_refs):
        result = f"classOutputCons({kind_symbol}, {entrypoint_symbol}, {result})"
    return result


def maude_node_class_output_list(output_refs: list[tuple[str, str, str]]) -> str:
    result = "noNodeClassOutputs"
    for object_symbol, kind_symbol, entrypoint_symbol in reversed(output_refs):
        result = (
            f"nodeClassOutputCons({object_symbol}, {kind_symbol}, "
            f"{entrypoint_symbol}, {result})"
        )
    return result


def print_search(title: str, facts: list[str], target: str) -> None:
    print(f"--- {title}")
    print("search [1] in WHIPPLESCRIPT-GENERATED-LOWERED-IR :")
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
    graph, lowered = load_artifacts(
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
    effect_dependencies = graph.get("effect_dependencies", [])
    node_lowerings = lowered.get("node_lowerings", [])
    edge_lowerings = lowered.get("edge_lowerings", [])
    dependency_lowerings = lowered.get("dependency_lowerings", [])
    core_objects = lowered.get("core_objects", [])

    node_symbols = {
        node["node_id"]: symbols.symbol("GraphNode", "node", node["node_id"])
        for node in nodes
    }
    port_symbols = {
        port["port_id"]: symbols.symbol("PortId", "port", port["port_id"])
        for port in ports
    }
    object_symbols = {
        obj["object_id"]: symbols.symbol("CoreObjectId", "coreObj", obj["object_id"])
        for obj in core_objects
    }
    dependency_symbols = {
        dependency["dependency_ref"]: symbols.symbol(
            "DependencyId", "dep", dependency["dependency_ref"]
        )
        for dependency in effect_dependencies
    }
    nodes_by_id = {node["node_id"]: node for node in nodes}
    ports_by_id = {port["port_id"]: port for port in ports}
    dependencies_by_ref = {
        dependency["dependency_ref"]: dependency
        for dependency in effect_dependencies
    }
    catalog_lowering_by_id = catalog_lowerings(verifier_catalog)
    edges_by_ref = {
        edge_ref(edge["required_port_id"], edge["provided_port_id"]): edge
        for edge in edges
    }
    edges_by_required_node: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        required_port = ports_by_id.get(edge["required_port_id"])
        if not isinstance(required_port, dict):
            raise SystemExit(
                f"construct graph edge references unknown required port "
                f"{edge['required_port_id']!r}"
            )
        required_node_id = required_port.get("owner_node_id")
        if not isinstance(required_node_id, str) or required_node_id not in node_symbols:
            raise SystemExit(
                f"construct graph edge references unknown required node "
                f"{required_node_id!r}"
            )
        edges_by_required_node.setdefault(required_node_id, []).append(edge)
    node_owned_objects: dict[str, list[dict[str, Any]]] = {}
    for obj in core_objects:
        if obj["owner_kind"] == "node":
            node_owned_objects.setdefault(obj["owner_ref"], []).append(obj)

    edge_searches: list[tuple[str, list[str], str]] = []
    for lowering in edge_lowerings:
        required_port_id = lowering["required_port_id"]
        provided_port_id = lowering["provided_port_id"]
        edge = edge_for_lowering(edges_by_ref, required_port_id, provided_port_id)
        required_port = ports_by_id[required_port_id]
        required_node_symbol = node_symbols[required_port["owner_node_id"]]
        provider_node_symbol = node_symbols[edge["provider_node_id"]]
        required_port_symbol = port_symbols[required_port_id]
        provided_port_symbol = port_symbols[provided_port_id]
        facts = [
            f"edgeAccepted({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            f"coreRelationForEdge({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            f"edgeTypePreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            f"edgeResourcePreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            f"edgeCapabilityPreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            f"edgeVersionPreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            f"edgeSpanPreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            f"edgeCardinalityPreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            f"edgeProvenancePreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
        ]
        edge_searches.append((
            (
                "Generated edge lowering preservation for "
                f"{required_port_id} -> {provided_port_id}."
            ),
            facts,
            f"edgeLoweringPreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
        ))

    dependency_searches: list[tuple[str, list[str], str]] = []
    for lowering in dependency_lowerings:
        dependency_ref = lowering["dependency_ref"]
        dependency_symbol = dependency_symbols[dependency_ref]
        facts = [
            f"effectDependencyAccepted({graph_symbol}, {dependency_symbol})",
            f"dependencyEndpointPreserved({dependency_symbol})",
            f"dependencyPredicatePreserved({dependency_symbol})",
            f"dependencySpanPreserved({dependency_symbol})",
            f"dependencyProvenancePreserved({dependency_symbol})",
        ]
        dependency_searches.append((
            f"Generated dependency lowering preservation for {dependency_ref}.",
            facts,
            f"dependencyLoweringPreserved({dependency_symbol})",
        ))

    node_searches: list[tuple[str, list[str], str]] = []
    for lowering in node_lowerings:
        node_id = lowering["node_id"]
        node = nodes_by_id[node_id]
        node_symbol = node_symbols[node_id]
        required_edge_symbols: list[tuple[str, str, str, str]] = []
        for edge in edges_by_required_node.get(node_id, []):
            required_port_id = edge["required_port_id"]
            provided_port_id = edge["provided_port_id"]
            provider_node_id = edge["provider_node_id"]
            required_edge_symbols.append((
                node_symbol,
                port_symbols[required_port_id],
                node_symbols[provider_node_id],
                port_symbols[provided_port_id],
            ))
        lowering_class = maude_lowering_class(symbols, lowering["lowering_class"])
        catalog_lowering = catalog_lowering_by_id.get(lowering["lowering_class"])
        if not isinstance(catalog_lowering, dict):
            raise SystemExit(
                "generated lowered IR bridge has no platform catalog lowering "
                f"entry for class {lowering['lowering_class']!r}"
            )
        construct_family = maude_construct_family(symbols, node["construct_family"])
        owned_objects = node_owned_objects.get(node_id, [])
        facts = [
            f"nodeAccepted({graph_symbol}, {node_symbol})",
            maude_node_needs_edges(node_symbol, required_edge_symbols),
            f"nodeUsesLoweringClass({node_symbol}, {lowering_class})",
            f"nodeConstructFamily({node_symbol}, {construct_family})",
            maude_node_class_output(
                symbols,
                node_symbol,
                lowering_class,
                owned_objects,
                object_symbols,
            ),
            f"sourceSpanPreserved({node_symbol})",
            f"nodeResourcePreserved({node_symbol})",
            f"nodeVersionPreserved({node_symbol})",
            f"nodeCardinalityPreserved({node_symbol})",
            f"nodeProvenancePreserved({node_symbol})",
            f"terminalBindingPreserved({node_symbol})",
        ]
        facts.extend(
            lowering_class_profile_facts(
                symbols,
                node,
                catalog_lowering,
                lowering_class,
                construct_family,
                owned_objects,
            )
        )
        for (
            required_node_symbol,
            required_port_symbol,
            provider_node_symbol,
            provided_port_symbol,
        ) in required_edge_symbols:
            facts.append(
                f"edgeLoweringPreserved({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})"
            )
        node_searches.append((
            f"Generated node lowering preservation for {node_id}.",
            facts,
            f"loweringPreservedNode({graph_symbol}, {node_symbol})",
        ))

    object_symbols_in_order = [
        object_symbols[obj["object_id"]]
        for obj in core_objects
    ]
    boundary_facts = [
        maude_graph_emits_with_graph(graph_symbol, object_symbols_in_order),
        f"loweringDeterministic({graph_symbol})",
        f"loweredIrReportComplete({graph_symbol})",
        f"noRuntimeInputsDuringLowering({graph_symbol})",
    ]
    edge_owned_objects: dict[str, list[str]] = {}
    dependency_owned_objects: dict[str, list[str]] = {}
    for obj in core_objects:
        if obj["owner_kind"] == "edge":
            edge_owned_objects.setdefault(obj["owner_ref"], []).append(
                object_symbols[obj["object_id"]]
            )
        if obj["owner_kind"] == "dependency":
            dependency_owned_objects.setdefault(obj["owner_ref"], []).append(
                object_symbols[obj["object_id"]]
            )
    for ref, owned in edge_owned_objects.items():
        edge = edges_by_ref.get(ref)
        if edge is None:
            raise SystemExit(f"unknown edge owner ref {ref!r}")
        required_port_id = edge["required_port_id"]
        provided_port_id = edge["provided_port_id"]
        required_port = ports_by_id[required_port_id]
        required_node_symbol = node_symbols[required_port["owner_node_id"]]
        provider_node_symbol = node_symbols[edge["provider_node_id"]]
        required_port_symbol = port_symbols[required_port_id]
        provided_port_symbol = port_symbols[provided_port_id]
        boundary_facts.extend([
            f"graphContainsNode({graph_symbol}, {required_node_symbol})",
            f"edgeAccepted({required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            maude_edge_core_objects(
                required_node_symbol,
                required_port_symbol,
                provider_node_symbol,
                provided_port_symbol,
                owned,
            ),
        ])
    for ref, owned in dependency_owned_objects.items():
        dependency = dependencies_by_ref.get(ref)
        if dependency is None:
            raise SystemExit(f"unknown dependency owner ref {ref!r}")
        dependency_symbol = dependency_symbols[ref]
        boundary_facts.extend([
            f"effectDependencyAccepted({graph_symbol}, {dependency_symbol})",
            f"dependencyLoweringPreserved({dependency_symbol})",
            maude_dependency_core_objects(dependency_symbol, owned),
        ])

    for obj in core_objects:
        object_symbol = object_symbols[obj["object_id"]]
        kind_symbol = maude_core_kind(symbols, obj["object_kind"])
        owner_ref = obj["owner_ref"]
        boundary_facts.extend([
            f"emittedCoreObject({graph_symbol}, {object_symbol}, {kind_symbol})",
            f"allowedCoreObjectKind({kind_symbol})",
            f"coreObjectOwnerUnique({graph_symbol}, {object_symbol})",
        ])
        if obj["owner_kind"] == "node":
            node_symbol = node_symbols[owner_ref]
            owner_objects = [
                object_symbols[other["object_id"]]
                for other in core_objects
                if other["owner_kind"] == "node" and other["owner_ref"] == owner_ref
            ]
            boundary_facts.extend([
                f"graphContainsNode({graph_symbol}, {node_symbol})",
                maude_node_core_objects(node_symbol, owner_objects),
                f"coreObjectOwnedByNode({graph_symbol}, {object_symbol}, {node_symbol})",
            ])
        elif obj["owner_kind"] == "edge":
            edge = edges_by_ref.get(owner_ref)
            if edge is None:
                raise SystemExit(f"unknown edge owner ref {owner_ref!r}")
            required_port_id = edge["required_port_id"]
            provided_port_id = edge["provided_port_id"]
            required_port = ports_by_id[required_port_id]
            required_node_symbol = node_symbols[required_port["owner_node_id"]]
            provider_node_symbol = node_symbols[edge["provider_node_id"]]
            required_port_symbol = port_symbols[required_port_id]
            provided_port_symbol = port_symbols[provided_port_id]
            boundary_facts.extend([
                f"coreObjectOwnedByEdge({graph_symbol}, {object_symbol}, {required_node_symbol}, {required_port_symbol}, {provider_node_symbol}, {provided_port_symbol})",
            ])
        else:
            dependency = dependencies_by_ref.get(owner_ref)
            if dependency is None:
                raise SystemExit(f"unknown dependency owner ref {owner_ref!r}")
            dependency_symbol = dependency_symbols[owner_ref]
            boundary_facts.extend([
                f"coreObjectOwnedByDependency({graph_symbol}, {object_symbol}, {dependency_symbol})",
            ])

    graph_facts = [
        f"acceptedProgram({graph_symbol})",
        f"graphLoweringBoundaryOk({graph_symbol})",
        f"graphNodes({graph_symbol}, {maude_graph_node_list(list(node_symbols.values()))})",
    ]
    graph_facts.extend(
        f"loweringPreservedNode({graph_symbol}, {node_symbol})"
        for node_symbol in node_symbols.values()
    )
    runtime_handoff_facts = [
        f"loweringPreserved({graph_symbol})",
        maude_graph_emits_with_graph(graph_symbol, object_symbols_in_order),
    ]
    runtime_handoff_facts.extend(
        runtime_boundary_facts_from_inventory(graph_symbol, core_objects)
    )
    runtime_object_handoff_searches: list[tuple[str, list[str], str]] = []
    for obj in core_objects:
        object_symbol = object_symbols[obj["object_id"]]
        kind_symbol = maude_core_kind(symbols, obj["object_kind"])
        runtime_entrypoint_fact = maude_runtime_entrypoint_fact(symbols, obj, object_symbol)
        runtime_handoff_facts.extend([
            f"emittedCoreObject({graph_symbol}, {object_symbol}, {kind_symbol})",
            runtime_entrypoint_fact,
        ])
        runtime_object_handoff_searches.append((
            f"Generated runtime object handoff for {obj['object_id']}.",
            [
                f"emittedCoreObject({graph_symbol}, {object_symbol}, {kind_symbol})",
                runtime_entrypoint_fact,
            ],
            f"handoffObjectOk({graph_symbol}, {object_symbol})",
        ))

    print(f"load {root / 'models/maude/kernel.maude'}")
    print(f"load {root / 'models/maude/construct-grammar.maude'}")
    print(f"load {root / 'models/maude/construct-graph.maude'}")
    print(f"load {root / 'models/maude/construct-lowering.maude'}")
    print(f"load {root / 'models/maude/lowering-runtime-handoff.maude'}")
    print(f"load {root / 'models/maude/lowering-class-lifecycle.maude'}")
    print()
    print("mod WHIPPLESCRIPT-GENERATED-LOWERED-IR is")
    print("  including WHIPPLESCRIPT-LOWERING-CLASS-LIFECYCLE .")
    for line in symbols.emit_ops():
        print(line)
    print("endm")
    print()
    print("--- Generated from whip --json check lowered_ir_report.")
    for title, facts, target in [*edge_searches, *dependency_searches, *node_searches]:
        print_search(title, facts, target)
    print_search(
        "Generated lowered IR report boundary.",
        boundary_facts,
        f"graphLoweringBoundaryOk({graph_symbol})",
    )
    print_search(
        "Generated graph lowering preservation aggregation.",
        graph_facts,
        f"loweringPreserved({graph_symbol})",
    )
    for title, facts, target in runtime_object_handoff_searches:
        print_search(title, facts, target)
    print_search(
        "Generated runtime lifecycle handoff.",
        runtime_handoff_facts,
        f"lifecycleHandoffOk({graph_symbol})",
    )


def maude_graph_emits_with_graph(graph_symbol: str, object_symbols: list[str]) -> str:
    return f"graphEmits({graph_symbol}, {maude_core_object_list(object_symbols)})"


if __name__ == "__main__":
    main()
