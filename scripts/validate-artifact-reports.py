#!/usr/bin/env python3
"""Validate construct_graph and optional lowered_ir_report evidence in reports."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from artifact_admission import (
    is_sha256_digest,
    load_platform_construct_catalog,
    validate_contract_registry_shape,
    validate_empty_diagnostics,
    validate_package_contract_spine,
    validate_package_contract_platform,
)


def fail(message: str) -> None:
    raise SystemExit(message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report_entries(
    construct_bridge: ModuleType,
    root: Path,
    report_path: Path,
    entry_index: int | None,
) -> list[tuple[str, dict[str, Any]]]:
    report = json.loads(report_path.read_text())
    if isinstance(report, list):
        construct_bridge.validate_json_schema(
            root,
            "check_report_v0.schema.json",
            report,
            "check report",
        )
        if entry_index is not None:
            if entry_index < 0 or entry_index >= len(report):
                fail(
                    f"--entry-index {entry_index} is out of range for "
                    f"{report_path} with {len(report)} entr"
                    f"{'y' if len(report) == 1 else 'ies'}"
                )
            entry = report[entry_index]
            if not isinstance(entry, dict):
                fail(f"{report_path}[{entry_index}] is not an object")
            if entry.get("status") != "ok":
                fail(f"{report_path}[{entry_index}] was not ok")
            return [(f"{report_path}[{entry_index}]", entry)]
        entries = []
        for index, entry in enumerate(report):
            if not isinstance(entry, dict):
                fail(f"{report_path}[{index}] is not an object")
            if entry.get("status") == "ok":
                entries.append((f"{report_path}[{index}]", entry))
        if not entries:
            fail(f"{report_path} did not contain any successful report entries")
        return entries
    if isinstance(report, dict) and report.get("schema") == "whipplescript.verified_artifacts.v0":
        construct_bridge.validate_json_schema(
            root,
            "verified_artifacts_v0.schema.json",
            report,
            "verified artifact bundle",
        )
        entries_value = report.get("entries")
        if not isinstance(entries_value, list):
            fail(f"{report_path}.entries must be an array")
        if entry_index is not None:
            if entry_index < 0 or entry_index >= len(entries_value):
                fail(
                    f"--entry-index {entry_index} is out of range for "
                    f"{report_path} with {len(entries_value)} entr"
                    f"{'y' if len(entries_value) == 1 else 'ies'}"
                )
            entry = entries_value[entry_index]
            if not isinstance(entry, dict):
                fail(f"{report_path}[{entry_index}] is not an object")
            return [(f"{report_path}[{entry_index}]", entry)]
        entries = []
        for index, entry in enumerate(entries_value):
            if not isinstance(entry, dict):
                fail(f"{report_path}[{index}] is not an object")
            entries.append((f"{report_path}[{index}]", entry))
        if not entries:
            fail(f"{report_path} did not contain any verified artifact entries")
        return entries
    if isinstance(report, dict):
        construct_bridge.validate_json_schema(
            root,
            "compile_report_v0.schema.json",
            report,
            "compile report",
        )
        if report.get("status") == "error":
            fail(f"{report_path} was not ok")
        return [(str(report_path), report)]
    fail(
        f"{report_path} is not a check report array, compile report object, "
        "or verified artifact bundle"
    )


def diagnostic_error_codes(artifact: dict[str, Any]) -> list[str]:
    codes = []
    for diagnostic in artifact.get("diagnostics", []):
        if isinstance(diagnostic, dict) and diagnostic.get("severity") == "error":
            codes.append(str(diagnostic.get("code", "unknown")))
    return codes


def stable_hash_hex(value: str) -> str:
    # Mirrors the Rust `stable_hash_hex`: SHA-256 truncated to 128 bits (the
    # FNV-collision hardening swap). Extend BOTH mirrors together.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def validate_report_identity(label: str, entry: dict[str, Any]) -> None:
    snapshot = entry.get("snapshot")
    ir_hash = entry.get("ir_hash")
    source_hash = entry.get("source_hash")
    if not isinstance(snapshot, str):
        fail(f"{label}.snapshot must be a string")
    if not isinstance(ir_hash, str) or not is_stable_digest(ir_hash):
        fail(f"{label}.ir_hash must be a 32-character lowercase hex digest")
    if not isinstance(source_hash, str) or not is_stable_digest(source_hash):
        fail(f"{label}.source_hash must be a 32-character lowercase hex digest")
    expected_ir_hash = stable_hash_hex(snapshot)
    if ir_hash != expected_ir_hash:
        fail(
            f"{label}.ir_hash must match embedded snapshot hash: "
            f"got {ir_hash!r}, expected {expected_ir_hash!r}"
        )


def is_stable_digest(value: str) -> bool:
    return len(value) == 32 and all(ch in "0123456789abcdef" for ch in value)


def validate_artifact_identity(
    root: Path,
    verifier_catalog: dict[str, Any],
    label: str,
    entry: dict[str, Any],
) -> None:
    graph = entry["construct_graph"]
    lowered = entry.get("lowered_ir_report")
    package_contract = entry.get("package_contract")
    if not isinstance(package_contract, dict):
        fail(f"{label}.package_contract must be an object")
    contract_registry = entry.get("contract_registry")
    if not isinstance(contract_registry, dict):
        fail(f"{label}.contract_registry must be an object")
    validate_contract_registry_shape(contract_registry, f"{label}.contract_registry")
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
    if embedded_registry != contract_registry:
        fail(f"{label}.package_contract.contract_registry must match contract_registry")
    validate_empty_diagnostics(package_contract, "diagnostics", f"{label}.package_contract")
    validate_empty_diagnostics(
        embedded_registry,
        "diagnostics",
        f"{label}.package_contract.contract_registry",
    )
    validate_empty_diagnostics(contract_registry, "diagnostics", f"{label}.contract_registry")
    package_contract_digest = package_contract.get("package_contract_digest")
    if not isinstance(package_contract_digest, str) or not is_sha256_digest(package_contract_digest):
        fail(
            f"{label}.package_contract.package_contract_digest must be a "
            "64-character lowercase hex digest"
        )
    digest_body = dict(package_contract)
    digest_body.pop("package_contract_digest", None)
    expected_package_contract_digest = hashlib.sha256(
        canonical_json(digest_body).encode("utf-8")
    ).hexdigest()
    if package_contract_digest != expected_package_contract_digest:
        fail(
            f"{label}.package_contract.package_contract_digest does not match "
            "the embedded package contract"
        )
    source_digest = graph.get("source_digest")
    if not isinstance(source_digest, str) or not is_sha256_digest(source_digest):
        fail(f"{label} construct_graph.source_digest must be a 64-character lowercase hex digest")
    graph_id = graph.get("graph_id")
    expected_graph_id = f"construct_graph:{source_digest}"
    if graph_id != expected_graph_id:
        fail(
            f"{label} construct_graph.graph_id must be {expected_graph_id!r}, "
            f"got {graph_id!r}"
        )
    if graph.get("package_contract_digest") != package_contract_digest:
        fail(
            f"{label} construct_graph.package_contract_digest does not match "
            "package_contract.package_contract_digest"
        )
    if graph.get("package_lock_digest") != package_contract.get("package_lock_digest"):
        fail(
            f"{label} construct_graph.package_lock_digest does not match "
            "package_contract.package_lock_digest"
        )
    if isinstance(lowered, dict):
        lowered_graph_id = lowered.get("graph_id")
        accepted_program_digest = lowered.get("accepted_program_digest")
        expected_program_digest = hashlib.sha256(
            f"{lowered_graph_id}\n{entry['snapshot']}".encode("utf-8")
        ).hexdigest()
        if accepted_program_digest != expected_program_digest:
            fail(
                f"{label} lowered_ir_report.accepted_program_digest does not match "
                "graph_id + snapshot"
            )


def validate_entry(
    construct_bridge: ModuleType,
    lowered_bridge: ModuleType,
    root: Path,
    verifier_catalog: dict[str, Any],
    label: str,
    entry: dict[str, Any],
) -> None:
    graph = entry.get("construct_graph")
    lowered = entry.get("lowered_ir_report")
    if not isinstance(graph, dict):
        fail(f"{label} has no construct_graph")
    if lowered is not None and not isinstance(lowered, dict):
        fail(f"{label}.lowered_ir_report must be an object")

    validate_report_identity(label, entry)
    validate_artifact_identity(root, verifier_catalog, label, entry)

    construct_bridge.validate_json_schema(
        root,
        "package_contract_v0.schema.json",
        entry["package_contract"],
        "package contract",
    )
    construct_bridge.validate_json_schema(
        root,
        "construct_graph_v0.schema.json",
        graph,
        "construct graph",
    )

    graph_errors = diagnostic_error_codes(graph)
    if graph_errors:
        fail(f"{label} construct graph has validator errors: {', '.join(graph_errors)}")

    construct_bridge.validate_construct_graph_trace(graph, verifier_catalog)
    if lowered is not None:
        lowered_bridge.validate_json_schema(
            root,
            "lowered_ir_report_v0.schema.json",
            lowered,
            "lowered IR report",
        )
        lowered_bridge.validate_artifact_identity(graph, lowered)
        lowered_errors = diagnostic_error_codes(lowered)
        if lowered_errors:
            fail(f"{label} lowered IR report has validator errors: {', '.join(lowered_errors)}")
        lowered_bridge.validate_lowered_ir_trace(graph, lowered)


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
        "--entry-index",
        type=int,
        default=None,
        help="validate only one zero-based check-report or verified-artifact entry",
    )
    parser.add_argument("reports", nargs="+", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    verifier_catalog = load_platform_construct_catalog(root, args.platform_catalog)
    construct_bridge = load_module(
        root / "scripts" / "construct-graph-to-maude.py",
        "whipplescript_construct_graph_bridge",
    )
    lowered_bridge = load_module(
        root / "scripts" / "lowered-ir-to-maude.py",
        "whipplescript_lowered_ir_bridge",
    )
    validated = 0
    for report_path in args.reports:
        for label, entry in report_entries(
            construct_bridge,
            root,
            report_path,
            args.entry_index,
        ):
            validate_entry(
                construct_bridge,
                lowered_bridge,
                root,
                verifier_catalog,
                label,
                entry,
            )
            validated += 1
            print(f"validated artifact evidence for {label}")
    print(f"validated artifact evidence in {validated} report entr{'y' if validated == 1 else 'ies'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            raise SystemExit(1)
        raise
