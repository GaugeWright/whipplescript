#!/usr/bin/env python3
"""Lower a package_contract artifact into Maude package-contract obligations."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from artifact_admission import (
    is_sha256_digest,
    load_platform_construct_catalog,
    validate_empty_diagnostics,
    validate_package_contract_platform,
    validate_package_contract_spine,
)

try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError, ValidationError
except Exception as exc:
    raise SystemExit(
        "python jsonschema package is required; run under `nix develop` or "
        f"install `requirements-dev.txt`: {exc}"
    )


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


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


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


def load_package_contract(
    root: Path,
    verifier_catalog: dict[str, Any],
    report_path: Path,
) -> dict[str, Any]:
    report = json.loads(report_path.read_text())
    if not isinstance(report, dict):
        raise SystemExit(f"{report_path} must be a package check or report object")
    if report.get("schema") == "whipplescript.package_check.v0":
        validate_json_schema(root, "package_check_v0.schema.json", report, "package check")
        if report.get("status") != "ok":
            raise SystemExit(f"{report_path} package check was not ok")
        package_contract = report.get("package_contract")
        if not isinstance(package_contract, dict):
            raise SystemExit(f"{report_path}.package_contract must be an object")
        if report.get("contract_registry") != package_contract.get("contract_registry"):
            raise SystemExit(
                f"{report_path}.contract_registry must match package_contract.contract_registry"
            )
    elif "package_contract" in report:
        schema_name = (
            "compile_report_v0.schema.json"
            if report.get("schema") == "whipplescript.compile_report.v0"
            else "package_check_v0.schema.json"
        )
        validate_json_schema(root, schema_name, report, "report")
        package_contract = report.get("package_contract")
    else:
        package_contract = report
        validate_json_schema(
            root,
            "package_contract_v0.schema.json",
            package_contract,
            "package contract",
        )
    if not isinstance(package_contract, dict):
        raise SystemExit(f"{report_path} has no package_contract object")
    validate_json_schema(
        root,
        "package_contract_v0.schema.json",
        package_contract,
        "package contract",
    )
    registry = validate_package_contract_spine(package_contract, "package_contract")
    validate_package_contract_platform(
        root,
        verifier_catalog,
        package_contract,
        "package_contract",
    )
    validate_empty_diagnostics(package_contract, "diagnostics", "package_contract")
    validate_empty_diagnostics(
        registry,
        "diagnostics",
        "package_contract.contract_registry",
    )
    digest = package_contract.get("package_contract_digest")
    if not isinstance(digest, str) or not is_sha256_digest(digest):
        raise SystemExit("package_contract.package_contract_digest must be a sha256 digest")
    digest_body = dict(package_contract)
    digest_body.pop("package_contract_digest", None)
    expected_digest = hashlib.sha256(canonical_json(digest_body).encode("utf-8")).hexdigest()
    if digest != expected_digest:
        raise SystemExit("package_contract.package_contract_digest does not match body")
    return package_contract


def string_array(value: dict[str, Any], key: str) -> list[str]:
    array = value.get(key)
    if not isinstance(array, list):
        return []
    return [item for item in array if isinstance(item, str) and item]


def require_string(value: dict[str, Any], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise SystemExit(f"{label}.{key} must be a non-empty string")
    return item


def first_source_keyword(contract: dict[str, Any]) -> str:
    source_forms = string_array(contract, "source_forms")
    if not source_forms:
        raise SystemExit(f"effect contract {contract.get('id')!r} has no source_forms")
    return source_forms[0]


def contract_capability(contract: dict[str, Any]) -> str:
    capabilities = string_array(contract, "required_capabilities")
    if len(capabilities) != 1:
        raise SystemExit(
            "generated package-contract bridge currently supports exactly one "
            f"required capability per effect contract, got {capabilities!r} "
            f"for {contract.get('id')!r}"
        )
    return capabilities[0]


def print_search(title: str, facts: list[str], target: str) -> None:
    print(f"--- {title}")
    print("search [1] in WHIPPLESCRIPT-GENERATED-PACKAGE-CONTRACT :")
    print("  " + "\n  ".join(facts))
    print("  =>*")
    print("  C:Cfg")
    print(f"  {target} .")
    print()


def package_effect_facts(
    decl_symbol: str,
    keyword_symbol: str,
    effect_symbol: str,
    type_symbol: str,
    capability_symbol: str,
    version_symbol: str,
) -> list[str]:
    return [
        f"packageDeclCandidate({decl_symbol})",
        f"packageDeclKeyword({decl_symbol}, {keyword_symbol})",
        f"deterministicParse({decl_symbol})",
        f"noKeywordConflict({decl_symbol})",
        f"declarativeLowering({decl_symbol})",
        f"noCustomControlFlow({decl_symbol})",
        f"noHiddenAuthority({decl_symbol})",
        f"noDirectFactWrite({decl_symbol})",
        f"lockedContractVersion({decl_symbol}, {version_symbol})",
        f"declaredCapability({decl_symbol}, {capability_symbol})",
        f"typedEffectContract({decl_symbol}, {effect_symbol}, {type_symbol}, {version_symbol})",
        f"requiredEffectCapability({effect_symbol}, {capability_symbol})",
    ]


def executable_construct_facts(
    decl_symbol: str,
    keyword_symbol: str,
    effect_symbol: str,
    type_symbol: str,
    capability_symbol: str,
    version_symbol: str,
) -> list[str]:
    return [
        f"packageDeclCandidate({decl_symbol})",
        f"packageDeclKeyword({decl_symbol}, {keyword_symbol})",
        f"capabilityCallDeclaration({decl_symbol}, {keyword_symbol}, ruleBodyScope, {effect_symbol}, {capability_symbol})",
        f"noKeywordConflict({decl_symbol})",
        "validDeclarationScope(ruleBodyScope)",
        f"validDeclarationFields({decl_symbol})",
        f"noHiddenAuthority({decl_symbol})",
        f"noDirectFactWrite({decl_symbol})",
        f"lockedContractVersion({decl_symbol}, {version_symbol})",
        f"declaredCapability({decl_symbol}, {capability_symbol})",
        f"typedEffectContract({decl_symbol}, {effect_symbol}, {type_symbol}, {version_symbol})",
        f"requiredEffectCapability({effect_symbol}, {capability_symbol})",
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--platform-catalog",
        type=Path,
        default=None,
        help="compiler-emitted platform catalog from `whip package catalog`",
    )
    parser.add_argument("report", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    verifier_catalog = load_platform_construct_catalog(root, args.platform_catalog)
    package_contract = load_package_contract(root, verifier_catalog, args.report)
    registry = package_contract["contract_registry"]
    symbols = SymbolTable()

    contracts = registry.get("effect_contracts", [])
    if not isinstance(contracts, list):
        raise SystemExit("package_contract.contract_registry.effect_contracts must be an array")
    constructs = registry.get("constructs", [])
    if not isinstance(constructs, list):
        raise SystemExit("package_contract.contract_registry.constructs must be an array")

    contract_by_id: dict[str, dict[str, Any]] = {}
    for contract in contracts:
        if not isinstance(contract, dict):
            raise SystemExit("effect contract entries must be objects")
        contract_id = require_string(contract, "id", "effect contract")
        if contract_id in contract_by_id:
            raise SystemExit(f"duplicate effect contract {contract_id!r}")
        if contract.get("effect_kind") != "capability.call":
            raise SystemExit(
                f"unsupported effect_kind {contract.get('effect_kind')!r} for {contract_id!r}"
            )
        if contract.get("validation") != "runtime_boundary":
            raise SystemExit(
                f"unsupported validation {contract.get('validation')!r} for {contract_id!r}"
            )
        contract_by_id[contract_id] = contract

    searches: list[tuple[str, list[str], str]] = []
    for contract_id, contract in sorted(contract_by_id.items()):
        capability = contract_capability(contract)
        version = require_string(contract, "version", f"effect contract {contract_id}")
        output_schema = require_string(
            contract,
            "output_schema",
            f"effect contract {contract_id}",
        )
        decl_symbol = symbols.symbol("PackageDeclId", "pkgDecl", f"effect:{contract_id}")
        keyword_symbol = symbols.symbol(
            "Keyword",
            "keyword",
            f"source:{first_source_keyword(contract)}",
        )
        effect_symbol = symbols.symbol("EffectId", "effect", contract_id)
        type_symbol = symbols.symbol("TypeId", "type", output_schema)
        capability_symbol = symbols.symbol("CapabilityId", "cap", capability)
        version_symbol = symbols.symbol("ContractVersion", "version", version)
        facts = package_effect_facts(
            decl_symbol,
            keyword_symbol,
            effect_symbol,
            type_symbol,
            capability_symbol,
            version_symbol,
        )
        searches.append((
            f"Generated package effect-contract acceptance for {contract_id}.",
            facts,
            (
                f"acceptedPackageContract({decl_symbol})\n  "
                f"registeredEffectContract({effect_symbol}, {type_symbol}, "
                f"{capability_symbol}, {version_symbol})"
            ),
        ))
        searches.append((
            f"Generated package effect-contract source lowering for {contract_id}.",
            facts + [f"sourceEffect({decl_symbol}, {effect_symbol})"],
            (
                f"graph(g1, {effect_symbol})\n  "
                f"expectsOutput({effect_symbol}, {type_symbol}, {version_symbol})"
            ),
        ))

    for construct in constructs:
        if not isinstance(construct, dict):
            raise SystemExit("construct registry entries must be objects")
        construct_id = require_string(construct, "id", "construct")
        if construct.get("lowering_target") != "capability_call":
            raise SystemExit(
                f"unsupported construct lowering_target {construct.get('lowering_target')!r} "
                f"for {construct_id!r}"
            )
        if construct.get("scope") != "rule_body":
            raise SystemExit(
                f"unsupported construct scope {construct.get('scope')!r} for {construct_id!r}"
            )
        capability = require_string(construct, "target_capability", f"construct {construct_id}")
        contract = contract_by_id.get(capability)
        if contract is None:
            raise SystemExit(
                f"construct {construct_id!r} target_capability {capability!r} "
                "does not match an effect contract"
            )
        version = require_string(construct, "version", f"construct {construct_id}")
        if version != require_string(contract, "version", f"effect contract {capability}"):
            raise SystemExit(
                f"construct {construct_id!r} version {version!r} does not match "
                f"effect contract {capability!r}"
            )
        output_schema = require_string(
            contract,
            "output_schema",
            f"effect contract {capability}",
        )
        decl_symbol = symbols.symbol("PackageDeclId", "pkgDecl", f"construct:{construct_id}")
        keyword_symbol = symbols.symbol(
            "Keyword",
            "keyword",
            f"construct:{require_string(construct, 'keyword', f'construct {construct_id}')}",
        )
        effect_symbol = symbols.symbol("EffectId", "effect", capability)
        type_symbol = symbols.symbol("TypeId", "type", output_schema)
        capability_symbol = symbols.symbol("CapabilityId", "cap", capability)
        version_symbol = symbols.symbol("ContractVersion", "version", version)
        facts = executable_construct_facts(
            decl_symbol,
            keyword_symbol,
            effect_symbol,
            type_symbol,
            capability_symbol,
            version_symbol,
        )
        searches.append((
            f"Generated executable construct acceptance for {construct_id}.",
            facts,
            (
                f"acceptedExecutableDeclaration({decl_symbol})\n  "
                f"registeredEffectContract({effect_symbol}, {type_symbol}, "
                f"{capability_symbol}, {version_symbol})"
            ),
        ))
        searches.append((
            f"Generated executable construct source lowering for {construct_id}.",
            facts + [f"sourceEffect({decl_symbol}, {effect_symbol})"],
            (
                f"graph(g1, {effect_symbol})\n  "
                f"expectsOutput({effect_symbol}, {type_symbol}, {version_symbol})"
            ),
        ))

    print(f"load {root / 'models/maude/kernel.maude'}")
    print(f"load {root / 'models/maude/package-contract.maude'}")
    print()
    print("mod WHIPPLESCRIPT-GENERATED-PACKAGE-CONTRACT is")
    print("  including WHIPPLESCRIPT-PACKAGE-CONTRACT .")
    for line in symbols.emit_ops():
        print(line)
    print("endm")
    print()
    print("--- Generated from whip package check package_contract.")
    for title, facts, target in searches:
        print_search(title, facts, target)


if __name__ == "__main__":
    main()
