#!/usr/bin/env python3
"""Validate model_search ledgers in check/compile JSON reports."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any

from artifact_admission import load_platform_construct_catalog


ALLOWED_CATEGORIES = {
    "ir",
    "artifact.construct_graph",
    "artifact.lowered_ir",
    "artifact.platform_catalog",
}
ALLOWED_OUTCOMES = {"solution", "no_solution"}
ALLOWED_IR_PREDICATES = {
    "guard-true",
    "guard-false",
    "guard-error",
    "succeeds",
    "fails",
    "completes",
    "terminal-branch-match",
    "terminal-branch-miss",
    "terminal-branch-guard-false",
    "terminal-exhaustive-miss",
    "assertion-read-only",
    "revision-active-rule",
    "revision-stale-rule",
    "revision-effect-attribution",
    "revision-completes-cancelled",
    "workflow-complete",
    "workflow-complete-requires-action",
    "workflow-fail",
    "workflow-fail-requires-action",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or value < 0:
        fail(f"{label} must be a non-negative integer, got {value!r}")
    return value


def required_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def required_str(value: Any, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be a string, got {value!r}")
    return value


def optional_span(value: Any) -> tuple[int, int] | None:
    if not isinstance(value, dict):
        return None
    start = value.get("start")
    end = value.get("end")
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end < start:
        return None
    return (start, end)


def source_span(value: Any, label: str) -> tuple[int, int]:
    span = optional_span(value)
    if span is None:
        fail(f"{label} has invalid source_span: {value!r}")
    return span


def artifact_span(artifact: dict[str, Any]) -> tuple[int, int] | None:
    return optional_span(artifact.get("source_span"))


def graph_first_span(graph: dict[str, Any], label: str) -> tuple[int, int]:
    nodes = required_list(graph.get("nodes"), f"{label}.construct_graph.nodes")
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            fail(f"{label}.construct_graph.nodes[{index}] must be an object")
        span = artifact_span(node)
        if span is not None:
            return span
    return (0, 0)


def artifact_by_id(
    artifacts: list[Any],
    id_key: str,
    id_value: str,
    label: str,
) -> dict[str, Any] | None:
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            fail(f"{label}[{index}] must be an object")
        if artifact.get(id_key) == id_value:
            return artifact
    return None


def port_span(
    graph: dict[str, Any],
    port_id: str,
    fallback: tuple[int, int],
    label: str,
) -> tuple[int, int]:
    ports = required_list(graph.get("ports"), f"{label}.construct_graph.ports")
    port = artifact_by_id(ports, "port_id", port_id, f"{label}.construct_graph.ports")
    if port is None:
        return fallback
    return artifact_span(port) or fallback


def node_span(
    graph: dict[str, Any],
    node_id: str,
    fallback: tuple[int, int],
    label: str,
) -> tuple[int, int]:
    nodes = required_list(graph.get("nodes"), f"{label}.construct_graph.nodes")
    node = artifact_by_id(nodes, "node_id", node_id, f"{label}.construct_graph.nodes")
    if node is None:
        return fallback
    return artifact_span(node) or fallback


def dependency_span(
    graph: dict[str, Any],
    dependency_ref: str,
    fallback: tuple[int, int],
    label: str,
) -> tuple[int, int]:
    dependencies = required_list(
        graph.get("effect_dependencies"), f"{label}.construct_graph.effect_dependencies"
    )
    dependency = artifact_by_id(
        dependencies,
        "dependency_ref",
        dependency_ref,
        f"{label}.construct_graph.effect_dependencies",
    )
    if dependency is None:
        return fallback
    return artifact_span(dependency) or fallback


def effect_node_matches_effect_id(node_id: Any, effect_id: str) -> bool:
    if not isinstance(node_id, str):
        return False
    prefix = "effect:"
    if not node_id.startswith(prefix):
        return False
    return node_id.removeprefix(prefix).rsplit(":", 1)[-1] == effect_id


def dependency_predicate_for_ir_obligation(predicate: str) -> str | None:
    if predicate in {"succeeds", "fails", "completes"}:
        return predicate
    if predicate == "revision-completes-cancelled":
        return "completes"
    return None


def dependency_obligation_expected_span(
    entry: dict[str, Any],
    upstream: str,
    predicate: str,
    downstream: str,
    label: str,
) -> tuple[int, int] | None:
    dependency_predicate = dependency_predicate_for_ir_obligation(predicate)
    if dependency_predicate is None:
        return None
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        fail(f"{label} missing construct_graph object")
    dependencies = required_list(
        graph.get("effect_dependencies"),
        f"{label}.construct_graph.effect_dependencies",
    )
    matches: list[tuple[int, int]] = []
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            fail(f"{label}.construct_graph.effect_dependencies[{index}] must be an object")
        if dependency.get("predicate") != dependency_predicate:
            continue
        if not effect_node_matches_effect_id(dependency.get("upstream_node_id"), upstream):
            continue
        if not effect_node_matches_effect_id(dependency.get("downstream_node_id"), downstream):
            continue
        span = artifact_span(dependency)
        if span is not None:
            matches.append(span)
    if len(matches) != 1:
        return None
    return matches[0]


def assertion_obligation_expected_span(
    entry: dict[str, Any],
    upstream: str,
    predicate: str,
    downstream: str,
    label: str,
) -> tuple[int, int] | None:
    if predicate != "assertion-read-only" or downstream != "ruleCommitEvt":
        return None
    if not upstream.startswith("assertion"):
        return None
    try:
        assertion_index = int(upstream.removeprefix("assertion"))
    except ValueError:
        return None
    if assertion_index < 1:
        return None
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        fail(f"{label} missing construct_graph object")
    nodes = required_list(graph.get("nodes"), f"{label}.construct_graph.nodes")
    assertion_spans: list[tuple[int, int]] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            fail(f"{label}.construct_graph.nodes[{index}] must be an object")
        if node.get("construct_family") != "assertion":
            continue
        span = artifact_span(node)
        if span is not None:
            assertion_spans.append(span)
    if assertion_index > len(assertion_spans):
        return None
    return assertion_spans[assertion_index - 1]


def revision_rule_obligation_expected_span(
    entry: dict[str, Any],
    upstream: str,
    predicate: str,
    label: str,
) -> tuple[int, int] | None:
    if predicate not in {"revision-active-rule", "revision-stale-rule"}:
        return None
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        fail(f"{label} missing construct_graph object")
    nodes = required_list(graph.get("nodes"), f"{label}.construct_graph.nodes")
    matches: list[tuple[int, int]] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            fail(f"{label}.construct_graph.nodes[{index}] must be an object")
        if node.get("construct_family") != "rule":
            continue
        metadata = node.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("rule_name") != upstream:
            continue
        node_id = node.get("node_id")
        if not isinstance(node_id, str) or not node_id.endswith(":when0"):
            continue
        span = artifact_span(node)
        if span is not None:
            matches.append(span)
    if len(matches) != 1:
        return None
    return matches[0]


def revision_effect_obligation_expected_span(
    entry: dict[str, Any],
    upstream: str,
    predicate: str,
    downstream: str,
    label: str,
) -> tuple[int, int] | None:
    if predicate != "revision-effect-attribution" or downstream != "effectVersion":
        return None
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        fail(f"{label} missing construct_graph object")
    nodes = required_list(graph.get("nodes"), f"{label}.construct_graph.nodes")
    matches: list[tuple[int, int]] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            fail(f"{label}.construct_graph.nodes[{index}] must be an object")
        if node.get("construct_family") != "effect_operation":
            continue
        if not effect_node_matches_effect_id(node.get("node_id"), upstream):
            continue
        span = artifact_span(node)
        if span is not None:
            matches.append(span)
    if len(matches) != 1:
        return None
    return matches[0]


def compiler_anchor_spans(
    entry: dict[str, Any],
    predicate_prefix: str,
    required_refs: set[str],
    label: str,
) -> list[tuple[int, int]]:
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        fail(f"{label} missing construct_graph object")
    facts = required_list(graph.get("derived_facts"), f"{label}.construct_graph.derived_facts")
    spans: list[tuple[int, int]] = []
    for index, fact in enumerate(facts):
        if not isinstance(fact, dict):
            fail(f"{label}.construct_graph.derived_facts[{index}] must be an object")
        if fact.get("owner_subsystem") != "compiler":
            continue
        predicate_value = fact.get("predicate")
        if not isinstance(predicate_value, str) or not predicate_value.startswith(predicate_prefix):
            continue
        input_refs = fact.get("input_refs")
        if not isinstance(input_refs, list):
            continue
        refs = {value for value in input_refs if isinstance(value, str)}
        if not required_refs.issubset(refs):
            continue
        span = artifact_span({"source_span": fact.get("diagnostic_span")})
        if span is not None:
            spans.append(span)
    return spans


def guard_obligation_expected_span(
    entry: dict[str, Any],
    upstream: str,
    predicate: str,
    label: str,
) -> tuple[int, int] | None:
    if predicate not in {"guard-true", "guard-false", "guard-error"}:
        return None
    spans = compiler_anchor_spans(
        entry,
        "model_search.guard_source:",
        {f"rule:{upstream}", "kind:guard"},
        label,
    )
    if len(spans) != 1:
        return None
    return spans[0]


def terminal_tag_from_description(rule_name: str, description: str) -> str | None:
    prefix = f"{rule_name} terminal "
    if not description.startswith(prefix):
        return None
    rest = description.removeprefix(prefix)
    for suffix in [
        " branch commits on matching tag",
        " branch misses on other tag",
        " false guard cannot commit",
        " exhaustive miss diagnoses",
    ]:
        if rest.endswith(suffix):
            tag = rest[: -len(suffix)]
            return tag or None
    return None


def terminal_branch_obligation_expected_span(
    entry: dict[str, Any],
    description: str,
    upstream: str,
    predicate: str,
    label: str,
) -> tuple[int, int] | None:
    if predicate not in {
        "terminal-branch-match",
        "terminal-branch-miss",
        "terminal-branch-guard-false",
        "terminal-exhaustive-miss",
    }:
        return None
    tag = terminal_tag_from_description(upstream, description)
    if tag is None:
        return None
    spans = compiler_anchor_spans(
        entry,
        "model_search.terminal_branch_source:",
        {f"rule:{upstream}", f"tag:{tag}", "kind:terminal_branch"},
        label,
    )
    if len(spans) != 1:
        return None
    return spans[0]


def ir_obligation_expected_artifact_span(
    entry: dict[str, Any],
    description: str,
    upstream: str,
    predicate: str,
    downstream: str,
    label: str,
) -> tuple[str, tuple[int, int]] | None:
    checks = [
        (
            "dependency",
            dependency_obligation_expected_span(entry, upstream, predicate, downstream, label),
        ),
        (
            "assertion",
            assertion_obligation_expected_span(entry, upstream, predicate, downstream, label),
        ),
        (
            "revision rule",
            revision_rule_obligation_expected_span(entry, upstream, predicate, label),
        ),
        (
            "revision effect",
            revision_effect_obligation_expected_span(entry, upstream, predicate, downstream, label),
        ),
        (
            "guard",
            guard_obligation_expected_span(entry, upstream, predicate, label),
        ),
        (
            "terminal branch",
            terminal_branch_obligation_expected_span(entry, description, upstream, predicate, label),
        ),
    ]
    matches = [(kind, span) for kind, span in checks if span is not None]
    if len(matches) != 1:
        return None
    return matches[0]


def validate_ir_artifact_source_spans(
    entry: dict[str, Any],
    obligations: list[Any],
    label: str,
) -> None:
    for index, obligation in enumerate(obligations, start=1):
        if not isinstance(obligation, dict) or obligation.get("category") != "ir":
            continue
        upstream = obligation.get("upstream")
        predicate = obligation.get("predicate")
        downstream = obligation.get("downstream")
        description = obligation.get("description")
        if not all(isinstance(value, str) for value in [description, upstream, predicate, downstream]):
            continue
        expected = ir_obligation_expected_artifact_span(
            entry,
            description,
            upstream,
            predicate,
            downstream,
            label,
        )
        if expected is None:
            continue
        kind, expected_span = expected
        actual = source_span(
            obligation.get("source_span"),
            f"{label}.model_search ir[{index}].source_span",
        )
        if actual != expected_span:
            fail(
                f"{label} IR {kind} obligation source_span mismatch for ir[{index}]: "
                f"got {actual!r}, expected {expected_span!r}"
            )


def expected_entry(
    description: str,
    upstream: str,
    predicate: str,
    downstream: str,
    span: tuple[int, int],
) -> dict[str, Any]:
    return {
        "description": description,
        "upstream": upstream,
        "predicate": predicate,
        "downstream": downstream,
        "source_span": span,
        "expected": "solution",
        "actual": "solution",
        "status": "ok",
    }


def expected_artifact_obligations(
    entry: dict[str, Any],
    label: str,
    verifier_catalog: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    graph = entry.get("construct_graph")
    lowered = entry.get("lowered_ir_report")
    if not isinstance(graph, dict):
        fail(f"{label} missing construct_graph object")
    if not isinstance(lowered, dict):
        fail(f"{label} missing lowered_ir_report object")
    nodes = required_list(graph.get("nodes"), f"{label}.construct_graph.nodes")
    edges = required_list(graph.get("edges"), f"{label}.construct_graph.edges")
    node_lowerings = required_list(
        lowered.get("node_lowerings"), f"{label}.lowered_ir_report.node_lowerings"
    )
    edge_lowerings = required_list(
        lowered.get("edge_lowerings"), f"{label}.lowered_ir_report.edge_lowerings"
    )
    dependency_lowerings = required_list(
        lowered.get("dependency_lowerings"),
        f"{label}.lowered_ir_report.dependency_lowerings",
    )
    graph_id = required_str(graph.get("graph_id"), f"{label}.construct_graph.graph_id")
    graph_span = graph_first_span(graph, label)

    construct_expected: list[dict[str, Any]] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            fail(f"{label}.construct_graph.nodes[{index}] must be an object")
        node_id = required_str(node.get("node_id"), f"{label}.construct_graph.nodes[{index}].node_id")
        construct_expected.append(
            expected_entry(
                f"Generated node acceptance for {node_id}.",
                graph_id,
                "nodeAccepted",
                node_id,
                artifact_span(node) or graph_span,
            )
        )
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            fail(f"{label}.construct_graph.edges[{index}] must be an object")
        required_port_id = required_str(
            edge.get("required_port_id"),
            f"{label}.construct_graph.edges[{index}].required_port_id",
        )
        provided_port_id = required_str(
            edge.get("provided_port_id"),
            f"{label}.construct_graph.edges[{index}].provided_port_id",
        )
        construct_expected.append(
            expected_entry(
                f"Generated edge acceptance for {required_port_id} -> {provided_port_id}.",
                required_port_id,
                "edgeAccepted",
                provided_port_id,
                port_span(graph, required_port_id, graph_span, label),
            )
        )
    construct_expected.append(
        expected_entry(
            "Generated graph aggregation from accepted nodes.",
            graph_id,
            "graphAccepted",
            graph_id,
            graph_span,
        )
    )
    construct_expected.append(
        expected_entry(
            "Generated accepted program from admitted graph and adequacy evidence.",
            graph_id,
            "acceptedProgram",
            graph_id,
            graph_span,
        )
    )

    lowered_expected: list[dict[str, Any]] = []
    for index, lowering in enumerate(edge_lowerings):
        if not isinstance(lowering, dict):
            fail(f"{label}.lowered_ir_report.edge_lowerings[{index}] must be an object")
        required_port_id = required_str(
            lowering.get("required_port_id"),
            f"{label}.lowered_ir_report.edge_lowerings[{index}].required_port_id",
        )
        provided_port_id = required_str(
            lowering.get("provided_port_id"),
            f"{label}.lowered_ir_report.edge_lowerings[{index}].provided_port_id",
        )
        lowered_expected.append(
            expected_entry(
                (
                    "Generated edge lowering preservation for "
                    f"{required_port_id} -> {provided_port_id}."
                ),
                required_port_id,
                "edgeLoweringPreserved",
                provided_port_id,
                port_span(graph, required_port_id, graph_span, label),
            )
        )
    for index, lowering in enumerate(dependency_lowerings):
        if not isinstance(lowering, dict):
            fail(f"{label}.lowered_ir_report.dependency_lowerings[{index}] must be an object")
        dependency_ref = required_str(
            lowering.get("dependency_ref"),
            f"{label}.lowered_ir_report.dependency_lowerings[{index}].dependency_ref",
        )
        lowered_expected.append(
            expected_entry(
                f"Generated dependency lowering preservation for {dependency_ref}.",
                graph_id,
                "dependencyLoweringPreserved",
                dependency_ref,
                dependency_span(graph, dependency_ref, graph_span, label),
            )
        )
    for index, lowering in enumerate(node_lowerings):
        if not isinstance(lowering, dict):
            fail(f"{label}.lowered_ir_report.node_lowerings[{index}] must be an object")
        node_id = required_str(
            lowering.get("node_id"),
            f"{label}.lowered_ir_report.node_lowerings[{index}].node_id",
        )
        lowered_expected.append(
            expected_entry(
                f"Generated node lowering preservation for {node_id}.",
                graph_id,
                "loweringPreservedNode",
                node_id,
                node_span(graph, node_id, graph_span, label),
            )
        )
    lowered_expected.append(
        expected_entry(
            "Generated lowered IR report boundary.",
            graph_id,
            "graphLoweringBoundaryOk",
            graph_id,
            graph_span,
        )
    )
    lowered_expected.append(
        expected_entry(
            "Generated graph lowering preservation aggregation.",
            graph_id,
            "loweringPreserved",
            graph_id,
            graph_span,
        )
    )
    core_objects = entry.get("lowered_ir_report", {}).get("core_objects", [])
    if not isinstance(core_objects, list):
        fail(f"{label}.lowered_ir_report.core_objects must be an array")
    for index, core_object in enumerate(core_objects):
        if not isinstance(core_object, dict):
            fail(f"{label}.lowered_ir_report.core_objects[{index}] must be an object")
        object_id = required_str(
            core_object.get("object_id"),
            f"{label}.lowered_ir_report.core_objects[{index}].object_id",
        )
        lowered_expected.append(
            expected_entry(
                f"Generated runtime object handoff for {object_id}.",
                graph_id,
                "handoffObjectOk",
                object_id,
                artifact_span(core_object) or graph_span,
            )
        )
    lowered_expected.append(
        expected_entry(
            "Generated runtime lifecycle handoff.",
            graph_id,
            "lifecycleHandoffOk",
            graph_id,
            graph_span,
        )
    )
    platform_expected: list[dict[str, Any]] = []
    lowerings = required_list(
        verifier_catalog.get("lowerings"),
        "verifier platform catalog.lowerings",
    )
    for index, lowering in enumerate(lowerings):
        if not isinstance(lowering, dict):
            fail(f"verifier platform catalog.lowerings[{index}] must be an object")
        lowering_id = required_str(
            lowering.get("id"),
            f"verifier platform catalog.lowerings[{index}].id",
        )
        platform_expected.append(
            expected_entry(
                f"Generated platform catalog lifecycle profile for {lowering_id}.",
                "platform_catalog",
                "catalogLoweringAccepted",
                lowering_id,
                graph_span,
            )
        )
    return {
        "artifact.construct_graph": construct_expected,
        "artifact.lowered_ir": lowered_expected,
        "artifact.platform_catalog": platform_expected,
    }


def expected_artifact_category_counts(
    entry: dict[str, Any],
    label: str,
    verifier_catalog: dict[str, Any],
) -> dict[str, int]:
    expected = expected_artifact_obligations(entry, label, verifier_catalog)
    return {
        "artifact.construct_graph": len(expected["artifact.construct_graph"]),
        "artifact.lowered_ir": len(expected["artifact.lowered_ir"]),
        "artifact.platform_catalog": len(expected["artifact.platform_catalog"]),
    }


def validate_obligation(
    obligation: Any,
    label: str,
    categories: Counter[str],
    outcomes: Counter[str],
    indexes_by_category: dict[str, list[int]],
    snapshot_facts: dict[str, Any],
) -> None:
    if not isinstance(obligation, dict):
        fail(f"{label} obligation must be an object")
    category = obligation.get("category")
    if category not in ALLOWED_CATEGORIES:
        fail(f"{label} obligation has unknown category {category!r}")
    index = obligation.get("index")
    if not isinstance(index, int) or index < 1:
        fail(f"{label} obligation index must be a positive integer, got {index!r}")
    expected = obligation.get("expected")
    actual = obligation.get("actual")
    if expected not in ALLOWED_OUTCOMES:
        fail(f"{label} obligation expected has invalid outcome {expected!r}")
    if actual not in ALLOWED_OUTCOMES:
        fail(f"{label} obligation actual has invalid outcome {actual!r}")
    if expected != actual:
        fail(f"{label} obligation expected/actual mismatch: {obligation!r}")
    if obligation.get("status") != "ok":
        fail(f"{label} obligation status must be ok: {obligation!r}")
    source_span = obligation.get("source_span")
    if not isinstance(source_span, dict):
        fail(f"{label} obligation missing source_span object")
    start = source_span.get("start")
    end = source_span.get("end")
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end < start:
        fail(f"{label} obligation has invalid source_span: {source_span!r}")
    if category == "ir":
        validate_ir_obligation(obligation, label, snapshot_facts)
    categories[category] += 1
    outcomes[actual] += 1
    indexes_by_category[category].append(index)


def validate_ir_obligation(
    obligation: dict[str, Any],
    label: str,
    snapshot_facts: dict[str, Any],
) -> None:
    for field in ("description", "upstream", "predicate", "downstream"):
        value = required_str(obligation.get(field), f"{label} obligation.{field}")
        if value == "":
            fail(f"{label} obligation.{field} must be non-empty")
    predicate = required_str(obligation.get("predicate"), f"{label} obligation.predicate")
    if predicate not in ALLOWED_IR_PREDICATES:
        fail(f"{label} obligation has unknown generated predicate {predicate!r}")
    upstream = required_str(obligation.get("upstream"), f"{label} obligation.upstream")
    downstream = required_str(obligation.get("downstream"), f"{label} obligation.downstream")
    if not snapshot_supports_obligation(snapshot_facts, predicate, upstream, downstream):
        fail(f"{label} obligation is not supported by the embedded snapshot")


def parse_snapshot_facts(snapshot: str) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "rules": {},
        "rule_order": [],
        "assertion_count": 0,
        "workflow_name": "",
        "workflow_contracts": [],
    }
    section = ""
    current_rule: str | None = None
    current_rule_subsection = ""

    for line in snapshot.splitlines():
        if not line.startswith(" "):
            parts = line.split()
            section = parts[0] if parts else ""
            if section == "workflow" and len(parts) > 1:
                facts["workflow_name"] = parts[1]
            current_rule = None
            current_rule_subsection = ""
            continue
        if section == "assertions":
            if line.startswith("  assert "):
                facts["assertion_count"] += 1
            continue
        if section == "workflow_contracts":
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("output", "failure"):
                facts["workflow_contracts"].append((parts[0], parts[1]))
            continue
        if section != "rules":
            continue
        if line.startswith("  rule "):
            current_rule = line.removeprefix("  rule ")
            if current_rule not in facts["rules"]:
                facts["rule_order"].append(current_rule)
                facts["rules"][current_rule] = new_snapshot_rule_facts()
            current_rule_subsection = ""
            continue
        if current_rule is None:
            continue
        rule = facts["rules"][current_rule]
        if line.startswith("    when "):
            rule["when_count"] += 1
            if " where " in line:
                rule["guarded_when_count"] += 1
            current_rule_subsection = ""
            continue
        if line == "    effects":
            current_rule_subsection = "effects"
            continue
        if line == "    dependencies":
            current_rule_subsection = "dependencies"
            continue
        if line == "    terminal_branches":
            current_rule_subsection = "terminal_branches"
            continue
        if line.startswith("    ") and not line.startswith("      "):
            current_rule_subsection = ""
            continue
        if not line.startswith("      "):
            continue
        value = line.removeprefix("      ")
        if current_rule_subsection == "effects":
            parts = value.split(maxsplit=1)
            if parts:
                if parts[0] not in rule["effects"]:
                    rule["effects_ordered"].append(parts[0])
                rule["effects"].add(parts[0])
        elif current_rule_subsection == "dependencies":
            dependency = parse_snapshot_dependency(value)
            if dependency is not None:
                rule["dependencies_ordered"].append(dependency)
                rule["dependencies"].add(dependency)
        elif current_rule_subsection == "terminal_branches" and value.startswith("case "):
            rule["terminal_branch_count"] += 1
            parts = value.split()
            tag = parts[2] if len(parts) > 2 else "_"
            guarded = " guard=-" not in value
            rule["terminal_branches_guarded"].append(guarded)
            rule["terminal_branches"].append((tag, guarded))
            if guarded:
                rule["guarded_terminal_branch_count"] += 1
    return facts


def new_snapshot_rule_facts() -> dict[str, Any]:
    return {
        "when_count": 0,
        "guarded_when_count": 0,
        "effects": set(),
        "effects_ordered": [],
        "dependencies": set(),
        "dependencies_ordered": [],
        "terminal_branch_count": 0,
        "guarded_terminal_branch_count": 0,
        "terminal_branches_guarded": [],
        "terminal_branches": [],
    }


def parse_snapshot_dependency(value: str) -> tuple[str, str, str] | None:
    if " --" not in value:
        return None
    upstream, rest = value.split(" --", 1)
    if "--> " not in rest:
        return None
    predicate, downstream = rest.split("--> ", 1)
    return (upstream, predicate, downstream)


def expected_ir_rows(facts: dict[str, Any]) -> list[tuple[str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str]] = []
    for rule_name in facts["rule_order"]:
        rule = facts["rules"][rule_name]
        for _ in range(rule["guarded_when_count"]):
            rows.append(
                (
                    f"{rule_name} true guard commits rule",
                    rule_name,
                    "guard-true",
                    "ruleCommitEvt",
                    "solution",
                )
            )
            rows.append(
                (
                    f"{rule_name} false guard cannot commit rule",
                    rule_name,
                    "guard-false",
                    "ruleCommitEvt",
                    "no_solution",
                )
            )
            rows.append(
                (
                    f"{rule_name} guard error emits diagnostic",
                    rule_name,
                    "guard-error",
                    "diagnostic",
                    "solution",
                )
            )
            rows.append(
                (
                    f"{rule_name} guard error cannot commit rule",
                    rule_name,
                    "guard-error",
                    "ruleCommitEvt",
                    "no_solution",
                )
            )
        for upstream, predicate, downstream in rule["dependencies_ordered"]:
            rows.append(
                (
                    f"{upstream} --{predicate}--> {downstream} cannot run before upstream terminal",
                    upstream,
                    predicate,
                    downstream,
                    "no_solution",
                )
            )
            rows.append(
                (
                    f"{upstream} --{predicate}--> {downstream} releases after satisfying terminal",
                    upstream,
                    predicate,
                    downstream,
                    "solution",
                )
            )
            if predicate in {"succeeds", "fails"}:
                rows.append(
                    (
                        f"{upstream} --{predicate}--> {downstream} does not release after non-satisfying terminal",
                        upstream,
                        predicate,
                        downstream,
                        "no_solution",
                    )
                )
        effects_ordered = rule["effects_ordered"]
        if rule["when_count"] > 0 and effects_ordered:
            first_effect = effects_ordered[0]
            rows.append(
                (
                    f"{rule_name} active revision scoped rule commits",
                    rule_name,
                    "revision-active-rule",
                    first_effect,
                    "solution",
                )
            )
            rows.append(
                (
                    f"{rule_name} stale revision scoped rule cannot commit",
                    rule_name,
                    "revision-stale-rule",
                    first_effect,
                    "no_solution",
                )
            )
            rows.append(
                (
                    f"{first_effect} old effect keeps revision attribution",
                    first_effect,
                    "revision-effect-attribution",
                    "effectVersion",
                    "no_solution",
                )
            )
            for upstream, predicate, downstream in rule["dependencies_ordered"]:
                if predicate == "completes":
                    rows.append(
                        (
                            f"{upstream} --completes--> {downstream} releases after revision cancellation",
                            upstream,
                            "revision-completes-cancelled",
                            downstream,
                            "solution",
                        )
                    )
        for tag, guarded in rule["terminal_branches"]:
            rows.append(
                (
                    f"{rule_name} terminal {tag} branch commits on matching tag",
                    rule_name,
                    "terminal-branch-match",
                    "ruleCommitEvt",
                    "solution",
                )
            )
            rows.append(
                (
                    f"{rule_name} terminal {tag} branch misses on other tag",
                    rule_name,
                    "terminal-branch-miss",
                    "ruleCommitEvt",
                    "no_solution",
                )
            )
            if guarded:
                rows.append(
                    (
                        f"{rule_name} terminal {tag} false guard cannot commit",
                        rule_name,
                        "terminal-branch-guard-false",
                        "ruleCommitEvt",
                        "no_solution",
                    )
                )
            rows.append(
                (
                    f"{rule_name} terminal {tag} exhaustive miss diagnoses",
                    rule_name,
                    "terminal-exhaustive-miss",
                    "diagnostic",
                    "solution",
                )
            )
    for assertion_index in range(1, facts["assertion_count"] + 1):
        assertion = f"assertion{assertion_index}"
        for result in ["aPass", "aFail", "aError"]:
            rows.append(
                (
                    f"assertion {assertion_index} {result} cannot mutate runtime state",
                    assertion,
                    "assertion-read-only",
                    "ruleCommitEvt",
                    "no_solution",
                )
            )
    # Workflow-terminal composition searches: the generator emits two searches
    # per declared output/failure contract, in contract order, after all rule
    # and assertion searches (mirrors append_composition_model_searches).
    workflow = facts.get("workflow_name", "")
    for kind, name in facts.get("workflow_contracts", []):
        if kind == "output":
            rows.append(
                (
                    f"{workflow} complete {name} reaches terminal",
                    workflow,
                    "workflow-complete",
                    "workflowCompletedEvt",
                    "solution",
                )
            )
            rows.append(
                (
                    f"{workflow} completion requires explicit complete {name}",
                    workflow,
                    "workflow-complete-requires-action",
                    "workflowCompletedEvt",
                    "no_solution",
                )
            )
        elif kind == "failure":
            rows.append(
                (
                    f"{workflow} fail {name} reaches terminal",
                    workflow,
                    "workflow-fail",
                    "workflowFailedEvt",
                    "solution",
                )
            )
            rows.append(
                (
                    f"{workflow} failure requires explicit fail {name}",
                    workflow,
                    "workflow-fail-requires-action",
                    "workflowFailedEvt",
                    "no_solution",
                )
            )
    return rows


def expected_ir_sequence(facts: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    return [(upstream, predicate, downstream, outcome) for _, upstream, predicate, downstream, outcome in expected_ir_rows(facts)]


def expected_ir_outcome_counts(
    facts: dict[str, Any],
) -> Counter[tuple[str, str, str, str]]:
    return +Counter(expected_ir_sequence(facts))


def expected_ir_endpoint_counts(facts: dict[str, Any]) -> Counter[tuple[str, str, str]]:
    counts: Counter[tuple[str, str, str]] = Counter()
    for (upstream, predicate, downstream, _), count in expected_ir_outcome_counts(facts).items():
        counts[(upstream, predicate, downstream)] += count
    return +counts


def expected_ir_predicate_counts(facts: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for (_, predicate, _, _), count in expected_ir_outcome_counts(facts).items():
        counts[predicate] += count
    return +counts


def expected_ir_search_count(facts: dict[str, Any]) -> int:
    return sum(expected_ir_outcome_counts(facts).values())


def format_ir_endpoint_counts(counts: Counter[tuple[str, str, str]]) -> dict[str, int]:
    return {
        f"{upstream} --{predicate}--> {downstream}": count
        for (upstream, predicate, downstream), count in sorted(counts.items())
    }


def format_ir_outcome_counts(counts: Counter[tuple[str, str, str, str]]) -> dict[str, int]:
    return {
        f"{upstream} --{predicate}--> {downstream} [{outcome}]": count
        for (upstream, predicate, downstream, outcome), count in sorted(counts.items())
    }


def snapshot_supports_obligation(
    facts: dict[str, Any],
    predicate: str,
    upstream: str,
    downstream: str,
) -> bool:
    if predicate in {"guard-true", "guard-false"}:
        return downstream == "ruleCommitEvt" and snapshot_rule_has_guarded_when(facts, upstream)
    if predicate == "guard-error":
        return downstream in {"diagnostic", "ruleCommitEvt"} and snapshot_rule_has_guarded_when(
            facts, upstream
        )
    if predicate in {"succeeds", "fails", "completes"}:
        return snapshot_has_dependency(facts, upstream, predicate, downstream)
    if predicate in {"terminal-branch-match", "terminal-branch-miss"}:
        return downstream == "ruleCommitEvt" and snapshot_rule_has_terminal_branch(facts, upstream)
    if predicate == "terminal-branch-guard-false":
        return downstream == "ruleCommitEvt" and snapshot_rule_has_guarded_terminal_branch(
            facts, upstream
        )
    if predicate == "terminal-exhaustive-miss":
        return downstream == "diagnostic" and snapshot_rule_has_terminal_branch(facts, upstream)
    if predicate == "assertion-read-only":
        return downstream == "ruleCommitEvt" and snapshot_has_assertion(facts, upstream)
    if predicate in {"revision-active-rule", "revision-stale-rule"}:
        rule = snapshot_rule(facts, upstream)
        return (
            rule is not None
            and rule["when_count"] > 0
            and downstream in rule["effects"]
        )
    if predicate == "revision-effect-attribution":
        return downstream == "effectVersion" and any(
            upstream in rule["effects"] for rule in facts["rules"].values()
        )
    if predicate == "revision-completes-cancelled":
        return snapshot_has_dependency(facts, upstream, "completes", downstream)
    if predicate in {"workflow-complete", "workflow-complete-requires-action"}:
        return (
            downstream == "workflowCompletedEvt"
            and upstream == facts.get("workflow_name", "")
            and any(kind == "output" for kind, _ in facts.get("workflow_contracts", []))
        )
    if predicate in {"workflow-fail", "workflow-fail-requires-action"}:
        return (
            downstream == "workflowFailedEvt"
            and upstream == facts.get("workflow_name", "")
            and any(kind == "failure" for kind, _ in facts.get("workflow_contracts", []))
        )
    return False


def snapshot_rule(facts: dict[str, Any], rule_name: str) -> dict[str, Any] | None:
    rule = facts["rules"].get(rule_name)
    return rule if isinstance(rule, dict) else None


def snapshot_rule_has_guarded_when(facts: dict[str, Any], rule_name: str) -> bool:
    rule = snapshot_rule(facts, rule_name)
    return rule is not None and rule["guarded_when_count"] > 0


def snapshot_rule_has_terminal_branch(facts: dict[str, Any], rule_name: str) -> bool:
    rule = snapshot_rule(facts, rule_name)
    return rule is not None and rule["terminal_branch_count"] > 0


def snapshot_rule_has_guarded_terminal_branch(facts: dict[str, Any], rule_name: str) -> bool:
    rule = snapshot_rule(facts, rule_name)
    return rule is not None and rule["guarded_terminal_branch_count"] > 0


def snapshot_has_dependency(
    facts: dict[str, Any],
    upstream: str,
    predicate: str,
    downstream: str,
) -> bool:
    return any(
        (upstream, predicate, downstream) in rule["dependencies"]
        for rule in facts["rules"].values()
    )


def snapshot_has_assertion(facts: dict[str, Any], upstream: str) -> bool:
    if not upstream.startswith("assertion"):
        return False
    try:
        index = int(upstream.removeprefix("assertion"))
    except ValueError:
        return False
    return 0 < index <= facts["assertion_count"]


def validate_ir_obligations_artifact(
    entry: dict[str, Any],
    obligations: list[Any],
    ir_searches: int,
    label: str,
    root: Path,
    schema_bridge: ModuleType,
) -> None:
    if ir_searches == 0:
        return
    artifact = entry.get("ir_model_search_obligations")
    if not isinstance(artifact, dict):
        fail(f"{label} missing ir_model_search_obligations artifact")
    schema_bridge.validate_json_schema(
        root,
        "ir_model_search_obligations_v0.schema.json",
        artifact,
        "IR model-search obligations artifact",
    )
    schema = required_str(
        artifact.get("schema"),
        f"{label}.ir_model_search_obligations.schema",
    )
    if schema != "whipplescript.ir_model_search_obligations.v0":
        fail(f"{label}.ir_model_search_obligations has invalid schema {schema!r}")
    source_hash = required_str(
        artifact.get("source_hash"),
        f"{label}.ir_model_search_obligations.source_hash",
    )
    if source_hash != required_str(entry.get("source_hash"), f"{label}.source_hash"):
        fail(f"{label}.ir_model_search_obligations.source_hash does not match report")
    ir_hash = required_str(
        artifact.get("ir_hash"),
        f"{label}.ir_model_search_obligations.ir_hash",
    )
    if ir_hash != required_str(entry.get("ir_hash"), f"{label}.ir_hash"):
        fail(f"{label}.ir_model_search_obligations.ir_hash does not match report")
    generator = required_str(
        artifact.get("generator"),
        f"{label}.ir_model_search_obligations.generator",
    )
    if generator == "":
        fail(f"{label}.ir_model_search_obligations.generator must be non-empty")
    artifact_obligations = required_list(
        artifact.get("obligations"),
        f"{label}.ir_model_search_obligations.obligations",
    )
    if len(artifact_obligations) != ir_searches:
        fail(
            f"{label}.ir_model_search_obligations count mismatch: "
            f"got {len(artifact_obligations)}, expected {ir_searches}"
        )
    ir_obligations = [
        obligation
        for obligation in obligations
        if isinstance(obligation, dict) and obligation.get("category") == "ir"
    ]
    if len(ir_obligations) != len(artifact_obligations):
        fail(f"{label} IR ledger count does not match ir_model_search_obligations")
    for index, (actual, expected) in enumerate(
        zip(ir_obligations, artifact_obligations, strict=True),
        start=1,
    ):
        if not isinstance(expected, dict):
            fail(f"{label}.ir_model_search_obligations[{index}] must be an object")
        expected_index = expected.get("index")
        if expected_index != index:
            fail(
                f"{label}.ir_model_search_obligations[{index}].index must be {index}, "
                f"got {expected_index!r}"
            )
        for field in ("description", "upstream", "predicate", "downstream", "expected"):
            actual_value = required_str(
                actual.get(field),
                f"{label}.model_search ir[{index}].{field}",
            )
            expected_value = required_str(
                expected.get(field),
                f"{label}.ir_model_search_obligations[{index}].{field}",
            )
            if actual_value != expected_value:
                fail(
                    f"{label} IR obligation mismatch for ir[{index}].{field}: "
                    f"got {actual_value!r}, expected {expected_value!r}"
                )
        actual_span = source_span(
            actual.get("source_span"),
            f"{label}.model_search ir[{index}].source_span",
        )
        expected_span = source_span(
            expected.get("source_span"),
            f"{label}.ir_model_search_obligations[{index}].source_span",
        )
        if actual_span != expected_span:
            fail(
                f"{label} IR obligation mismatch for ir[{index}].source_span: "
                f"got {actual_span!r}, expected {expected_span!r}"
            )


def validate_artifact_obligations_artifact(
    entry: dict[str, Any],
    obligations: list[Any],
    artifact_searches: int,
    label: str,
    root: Path,
    schema_bridge: ModuleType,
) -> None:
    if artifact_searches == 0:
        return
    artifact = entry.get("artifact_model_search_obligations")
    if not isinstance(artifact, dict):
        fail(f"{label} missing artifact_model_search_obligations artifact")
    schema_bridge.validate_json_schema(
        root,
        "artifact_model_search_obligations_v0.schema.json",
        artifact,
        "artifact model-search obligations artifact",
    )
    schema = required_str(
        artifact.get("schema"),
        f"{label}.artifact_model_search_obligations.schema",
    )
    if schema != "whipplescript.artifact_model_search_obligations.v0":
        fail(f"{label}.artifact_model_search_obligations has invalid schema {schema!r}")
    source_hash = required_str(
        artifact.get("source_hash"),
        f"{label}.artifact_model_search_obligations.source_hash",
    )
    if source_hash != required_str(entry.get("source_hash"), f"{label}.source_hash"):
        fail(f"{label}.artifact_model_search_obligations.source_hash does not match report")
    ir_hash = required_str(
        artifact.get("ir_hash"),
        f"{label}.artifact_model_search_obligations.ir_hash",
    )
    if ir_hash != required_str(entry.get("ir_hash"), f"{label}.ir_hash"):
        fail(f"{label}.artifact_model_search_obligations.ir_hash does not match report")
    package_contract = entry.get("package_contract")
    if not isinstance(package_contract, dict):
        fail(f"{label} missing package_contract")
    package_contract_digest = required_str(
        artifact.get("package_contract_digest"),
        f"{label}.artifact_model_search_obligations.package_contract_digest",
    )
    if package_contract_digest != required_str(
        package_contract.get("package_contract_digest"),
        f"{label}.package_contract.package_contract_digest",
    ):
        fail(
            f"{label}.artifact_model_search_obligations.package_contract_digest "
            "does not match report"
        )
    graph = entry.get("construct_graph")
    if not isinstance(graph, dict):
        fail(f"{label} missing construct_graph")
    graph_id = required_str(
        artifact.get("construct_graph_id"),
        f"{label}.artifact_model_search_obligations.construct_graph_id",
    )
    if graph_id != required_str(graph.get("graph_id"), f"{label}.construct_graph.graph_id"):
        fail(f"{label}.artifact_model_search_obligations.construct_graph_id does not match report")
    lowered = entry.get("lowered_ir_report")
    if not isinstance(lowered, dict):
        fail(f"{label} missing lowered_ir_report")
    accepted_program_digest = required_str(
        artifact.get("accepted_program_digest"),
        f"{label}.artifact_model_search_obligations.accepted_program_digest",
    )
    if accepted_program_digest != required_str(
        lowered.get("accepted_program_digest"),
        f"{label}.lowered_ir_report.accepted_program_digest",
    ):
        fail(
            f"{label}.artifact_model_search_obligations.accepted_program_digest "
            "does not match report"
        )
    generator = required_str(
        artifact.get("generator"),
        f"{label}.artifact_model_search_obligations.generator",
    )
    if generator == "":
        fail(f"{label}.artifact_model_search_obligations.generator must be non-empty")
    artifact_obligations = required_list(
        artifact.get("obligations"),
        f"{label}.artifact_model_search_obligations.obligations",
    )
    if len(artifact_obligations) != artifact_searches:
        fail(
            f"{label}.artifact_model_search_obligations count mismatch: "
            f"got {len(artifact_obligations)}, expected {artifact_searches}"
        )
    ledger_obligations = [
        obligation
        for obligation in obligations
        if isinstance(obligation, dict) and obligation.get("category") != "ir"
    ]
    if len(ledger_obligations) != len(artifact_obligations):
        fail(f"{label} artifact ledger count does not match artifact_model_search_obligations")
    for index, (actual, expected) in enumerate(
        zip(ledger_obligations, artifact_obligations, strict=True),
        start=1,
    ):
        if not isinstance(expected, dict):
            fail(f"{label}.artifact_model_search_obligations[{index}] must be an object")
        category = required_str(
            actual.get("category"),
            f"{label}.model_search artifact[{index}].category",
        )
        expected_category = required_str(
            expected.get("category"),
            f"{label}.artifact_model_search_obligations[{index}].category",
        )
        if category != expected_category:
            fail(
                f"{label} artifact obligation mismatch for artifact[{index}].category: "
                f"got {category!r}, expected {expected_category!r}"
            )
        if actual.get("index") != expected.get("index"):
            fail(
                f"{label} artifact obligation mismatch for {category}[{index}].index: "
                f"got {actual.get('index')!r}, expected {expected.get('index')!r}"
            )
        for field in ("description", "upstream", "predicate", "downstream", "expected"):
            actual_value = required_str(
                actual.get(field),
                f"{label}.model_search {category}[{index}].{field}",
            )
            expected_value = required_str(
                expected.get(field),
                f"{label}.artifact_model_search_obligations[{index}].{field}",
            )
            if actual_value != expected_value:
                fail(
                    f"{label} artifact obligation mismatch for {category}[{index}].{field}: "
                    f"got {actual_value!r}, expected {expected_value!r}"
                )
        actual_span = source_span(
            actual.get("source_span"),
            f"{label}.model_search {category}[{index}].source_span",
        )
        expected_span = source_span(
            expected.get("source_span"),
            f"{label}.artifact_model_search_obligations[{index}].source_span",
        )
        if actual_span != expected_span:
            fail(
                f"{label} artifact obligation mismatch for {category}[{index}].source_span: "
                f"got {actual_span!r}, expected {expected_span!r}"
            )


def compare_artifact_obligations(
    actual: list[dict[str, Any]],
    expected: dict[str, list[dict[str, Any]]],
    label: str,
) -> None:
    for category, expected_obligations in expected.items():
        actual_obligations = [
            obligation for obligation in actual if obligation.get("category") == category
        ]
        if len(actual_obligations) != len(expected_obligations):
            fail(
                f"{label} {category} obligation count mismatch: "
                f"got {len(actual_obligations)}, expected {len(expected_obligations)}"
            )
        for index, (actual_obligation, expected_obligation) in enumerate(
            zip(actual_obligations, expected_obligations, strict=True), start=1
        ):
            if actual_obligation.get("index") != index:
                fail(
                    f"{label} artifact obligation mismatch for {category}[{index}].index: "
                    f"got {actual_obligation.get('index')!r}, expected {index!r}"
                )
            for key in (
                "description",
                "upstream",
                "predicate",
                "downstream",
                "expected",
                "actual",
                "status",
            ):
                if actual_obligation.get(key) != expected_obligation[key]:
                    fail(
                        f"{label} artifact obligation mismatch for {category}[{index}].{key}: "
                        f"got {actual_obligation.get(key)!r}, expected {expected_obligation[key]!r}"
                    )
            actual_span = source_span(
                actual_obligation.get("source_span"),
                f"{label}.model_search {category}[{index}].source_span",
            )
            if actual_span != expected_obligation["source_span"]:
                fail(
                    f"{label} artifact obligation mismatch for "
                    f"{category}[{index}].source_span: "
                    f"got {actual_span!r}, expected {expected_obligation['source_span']!r}"
                )


def validate_model_search(
    entry: dict[str, Any],
    label: str,
    require_ok: bool,
    root: Path,
    schema_bridge: ModuleType,
    verifier_catalog: dict[str, Any],
) -> None:
    model_search = entry.get("model_search")
    if not isinstance(model_search, dict):
        fail(f"{label} missing model_search object")
    status = model_search.get("status")
    if status != "ok":
        if require_ok:
            fail(f"{label} model_search status must be ok, got {status!r}")
        return

    searches = nonnegative_int(model_search.get("searches"), f"{label}.model_search.searches")
    solutions = nonnegative_int(model_search.get("solutions"), f"{label}.model_search.solutions")
    no_solutions = nonnegative_int(
        model_search.get("no_solutions"), f"{label}.model_search.no_solutions"
    )
    ir_searches = nonnegative_int(
        model_search.get("ir_searches"), f"{label}.model_search.ir_searches"
    )
    artifact_searches = nonnegative_int(
        model_search.get("artifact_searches"), f"{label}.model_search.artifact_searches"
    )
    obligations = required_list(model_search.get("obligations"), f"{label}.model_search.obligations")
    if searches != len(obligations):
        fail(f"{label} searches={searches} but obligation count is {len(obligations)}")
    if searches != solutions + no_solutions:
        fail(
            f"{label} searches={searches} but solutions+no_solutions="
            f"{solutions + no_solutions}"
        )
    if searches != ir_searches + artifact_searches:
        fail(f"{label} searches={searches} but ir+artifact={ir_searches + artifact_searches}")

    categories: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    indexes_by_category: dict[str, list[int]] = defaultdict(list)
    snapshot = required_str(entry.get("snapshot"), f"{label}.snapshot")
    snapshot_facts = parse_snapshot_facts(snapshot)
    expected_ir_searches = expected_ir_search_count(snapshot_facts)
    if ir_searches != expected_ir_searches:
        fail(
            f"{label} ir_searches={ir_searches} but snapshot implies "
            f"{expected_ir_searches} generated IR searches"
        )
    for index, obligation in enumerate(obligations):
        validate_obligation(
            obligation,
            f"{label}.model_search.obligations[{index}]",
            categories,
            outcomes,
            indexes_by_category,
            snapshot_facts,
        )
    actual_ir_predicates = Counter(
        obligation["predicate"]
        for obligation in obligations
        if obligation["category"] == "ir"
    )
    expected_ir_predicates = expected_ir_predicate_counts(snapshot_facts)
    if actual_ir_predicates != expected_ir_predicates:
        fail(
            f"{label} IR predicate counts do not match snapshot: "
            f"got {dict(sorted(actual_ir_predicates.items()))}, "
            f"expected {dict(sorted(expected_ir_predicates.items()))}"
        )
    actual_ir_endpoints = Counter(
        (obligation["upstream"], obligation["predicate"], obligation["downstream"])
        for obligation in obligations
        if obligation["category"] == "ir"
    )
    expected_ir_endpoints = expected_ir_endpoint_counts(snapshot_facts)
    if actual_ir_endpoints != expected_ir_endpoints:
        fail(
            f"{label} IR endpoint counts do not match snapshot: "
            f"got {format_ir_endpoint_counts(actual_ir_endpoints)}, "
            f"expected {format_ir_endpoint_counts(expected_ir_endpoints)}"
        )
    actual_ir_outcomes = Counter(
        (
            obligation["upstream"],
            obligation["predicate"],
            obligation["downstream"],
            obligation["actual"],
        )
        for obligation in obligations
        if obligation["category"] == "ir"
    )
    expected_ir_outcomes = expected_ir_outcome_counts(snapshot_facts)
    if actual_ir_outcomes != expected_ir_outcomes:
        fail(
            f"{label} IR outcome counts do not match snapshot: "
            f"got {format_ir_outcome_counts(actual_ir_outcomes)}, "
            f"expected {format_ir_outcome_counts(expected_ir_outcomes)}"
        )
    actual_ir_sequence = [
        (
            obligation["upstream"],
            obligation["predicate"],
            obligation["downstream"],
            obligation["actual"],
        )
        for obligation in obligations
        if obligation["category"] == "ir"
    ]
    expected_ir_rows_list = expected_ir_rows(snapshot_facts)
    expected_ir_sequence_rows = [
        (upstream, predicate, downstream, outcome)
        for _, upstream, predicate, downstream, outcome in expected_ir_rows_list
    ]
    if actual_ir_sequence != expected_ir_sequence_rows:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(
                    zip(actual_ir_sequence, expected_ir_sequence_rows, strict=False),
                    start=1,
                )
                if actual != expected
            ),
            min(len(actual_ir_sequence), len(expected_ir_sequence_rows)) + 1,
        )
        fail(
            f"{label} IR obligation sequence does not match snapshot at row {mismatch}: "
            f"got {actual_ir_sequence[mismatch - 1] if mismatch <= len(actual_ir_sequence) else '<missing>'!r}, "
            f"expected {expected_ir_sequence_rows[mismatch - 1] if mismatch <= len(expected_ir_sequence_rows) else '<missing>'!r}"
        )
    actual_ir_descriptions = [
        obligation["description"]
        for obligation in obligations
        if obligation["category"] == "ir"
    ]
    expected_ir_descriptions = [
        description for description, _, _, _, _ in expected_ir_rows_list
    ]
    if actual_ir_descriptions != expected_ir_descriptions:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(
                    zip(actual_ir_descriptions, expected_ir_descriptions, strict=False),
                    start=1,
                )
                if actual != expected
            ),
            min(len(actual_ir_descriptions), len(expected_ir_descriptions)) + 1,
        )
        fail(
            f"{label} IR obligation descriptions do not match snapshot at row {mismatch}: "
            f"got {actual_ir_descriptions[mismatch - 1] if mismatch <= len(actual_ir_descriptions) else '<missing>'!r}, "
            f"expected {expected_ir_descriptions[mismatch - 1] if mismatch <= len(expected_ir_descriptions) else '<missing>'!r}"
        )

    if outcomes["solution"] != solutions or outcomes["no_solution"] != no_solutions:
        fail(
            f"{label} outcome counters do not match ledger: "
            f"{dict(outcomes)} vs solution={solutions}, no_solution={no_solutions}"
        )
    if categories["ir"] != ir_searches:
        fail(f"{label} ir_searches={ir_searches} but ledger has {categories['ir']}")
    artifact_total = (
        categories["artifact.construct_graph"]
        + categories["artifact.lowered_ir"]
        + categories["artifact.platform_catalog"]
    )
    if artifact_total != artifact_searches:
        fail(f"{label} artifact_searches={artifact_searches} but ledger has {artifact_total}")

    expected_artifact_counts = expected_artifact_category_counts(
        entry,
        label,
        verifier_catalog,
    )
    for category, expected_count in expected_artifact_counts.items():
        if categories[category] != expected_count:
            fail(
                f"{label} {category} obligations={categories[category]} "
                f"but expected {expected_count}"
            )
    for category, indexes in indexes_by_category.items():
        expected_indexes = list(range(1, len(indexes) + 1))
        if indexes != expected_indexes:
            fail(f"{label} {category} obligation indexes are not 1..n: {indexes!r}")
    validate_ir_obligations_artifact(
        entry,
        obligations,
        ir_searches,
        label,
        root,
        schema_bridge,
    )
    validate_artifact_obligations_artifact(
        entry,
        obligations,
        artifact_searches,
        label,
        root,
        schema_bridge,
    )
    validate_ir_artifact_source_spans(entry, obligations, label)
    compare_artifact_obligations(
        obligations,
        expected_artifact_obligations(entry, label, verifier_catalog),
        label,
    )

    print(
        f"validated {label} model_search ledger "
        f"({artifact_searches} artifact / {ir_searches} IR)"
    )


def successful_entries(
    report: Any,
    path: Path,
    root: Path,
    schema_bridge: ModuleType,
) -> list[tuple[str, dict[str, Any]]]:
    if isinstance(report, list):
        schema_bridge.validate_json_schema(
            root,
            "check_report_v0.schema.json",
            report,
            "check report",
        )
        entries = []
        for index, entry in enumerate(report):
            if not isinstance(entry, dict):
                fail(f"{path}[{index}] must be an object")
            if entry.get("status") == "ok":
                entries.append((f"{path}[{index}]", entry))
        return entries
    if isinstance(report, dict) and report.get("schema") == "whipplescript.verified_artifacts.v0":
        fail(f"{path} must be a check report array or compile report object")
    if isinstance(report, dict):
        schema_bridge.validate_json_schema(
            root,
            "compile_report_v0.schema.json",
            report,
            "compile report",
        )
        if report.get("status") == "error":
            return []
        return [(str(path), report)]
    fail(f"{path} must be a check report array or compile report object")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--platform-catalog",
        type=Path,
        default=None,
        help="compiler-emitted platform catalog from `whip package catalog`",
    )
    parser.add_argument(
        "--require-model-search",
        action="store_true",
        help="fail if a successful report entry does not include model_search",
    )
    parser.add_argument(
        "--require-ok",
        action="store_true",
        help="fail if model_search is present but did not complete successfully",
    )
    parser.add_argument("reports", nargs="+", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    schema_bridge = load_module(
        root / "scripts" / "construct-graph-to-maude.py",
        "whipplescript_model_search_schema_bridge",
    )
    artifact_context: tuple[ModuleType, ModuleType, ModuleType, dict[str, Any]] | None = None

    def require_artifact_context() -> tuple[ModuleType, ModuleType, ModuleType, dict[str, Any]]:
        nonlocal artifact_context
        if artifact_context is None:
            verifier_catalog = load_platform_construct_catalog(root, args.platform_catalog)
            artifact_validator = load_module(
                root / "scripts" / "validate-artifact-reports.py",
                "whipplescript_artifact_report_validator",
            )
            construct_bridge = artifact_validator.load_module(
                root / "scripts" / "construct-graph-to-maude.py",
                "whipplescript_construct_graph_bridge_for_model_search",
            )
            lowered_bridge = artifact_validator.load_module(
                root / "scripts" / "lowered-ir-to-maude.py",
                "whipplescript_lowered_ir_bridge_for_model_search",
            )
            artifact_context = (
                artifact_validator,
                construct_bridge,
                lowered_bridge,
                verifier_catalog,
            )
        return artifact_context

    for path in args.reports:
        report = json.loads(path.read_text())
        entries = successful_entries(report, path, root, schema_bridge)
        for label, entry in entries:
            if "model_search" not in entry:
                if args.require_model_search:
                    fail(f"{label} missing model_search")
                continue
            model_search = entry.get("model_search")
            verifier_catalog: dict[str, Any] | None = None
            if isinstance(model_search, dict) and model_search.get("status") == "ok":
                artifact_validator, construct_bridge, lowered_bridge, verifier_catalog = (
                    require_artifact_context()
                )
                artifact_validator.validate_entry(
                    construct_bridge,
                    lowered_bridge,
                    root,
                    verifier_catalog,
                    label,
                    entry,
                )
            if verifier_catalog is None:
                verifier_catalog = {}
            validate_model_search(
                entry,
                label,
                args.require_ok,
                root,
                schema_bridge,
                verifier_catalog,
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            raise SystemExit(1)
        raise
