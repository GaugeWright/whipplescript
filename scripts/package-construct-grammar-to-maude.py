#!/usr/bin/env python3
"""Lower package contract constructs into Maude construct-grammar obligations."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from artifact_admission import load_platform_construct_catalog


FAMILY = {
    "effect_operation": "effectOperation",
}

LOWERING = {
    "capability_call": "capabilityCall",
}


def load_package_bridge() -> ModuleType:
    path = Path(__file__).with_name("package-contract-to-maude.py")
    spec = importlib.util.spec_from_file_location("package_contract_to_maude", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKAGE_BRIDGE = load_package_bridge()


def construct_string(value: dict[str, Any], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise SystemExit(f"{label}.{key} must be a non-empty string")
    return item


def construct_array(value: dict[str, Any], key: str, label: str) -> list[dict[str, Any]]:
    item = value.get(key)
    if not isinstance(item, list):
        raise SystemExit(f"{label}.{key} must be an array")
    result: list[dict[str, Any]] = []
    for index, element in enumerate(item):
        if not isinstance(element, dict):
            raise SystemExit(f"{label}.{key}[{index}] must be an object")
        result.append(element)
    return result


def capability_requirement(construct: dict[str, Any], label: str) -> str:
    target = construct_string(construct, "target_capability", label)
    requirements = construct_array(construct, "requires", label)
    matching = [
        requirement
        for requirement in requirements
        if requirement.get("kind") == "Capability" and requirement.get("name") == target
    ]
    if len(matching) != 1:
        raise SystemExit(
            f"{label} must have exactly one Capability requirement matching "
            f"target_capability {target!r}"
        )
    return target


def has_only_capability_requirements(construct: dict[str, Any], capability: str) -> bool:
    requirements = construct_array(construct, "requires", "construct")
    return all(
        requirement.get("kind") == "Capability"
        and requirement.get("name") == capability
        for requirement in requirements
    )


def effect_handle_type(construct: dict[str, Any], label: str) -> str:
    provides = construct_array(construct, "provides", label)
    matching = [
        provided
        for provided in provides
        if provided.get("kind") == "EffectHandle"
        and isinstance(provided.get("type"), str)
        and provided.get("type")
    ]
    if len(matching) != 1:
        raise SystemExit(f"{label} must provide exactly one EffectHandle type")
    return str(matching[0]["type"])


def construct_acceptance_facts(
    construct_symbol: str,
    family_symbol: str,
    lowering_symbol: str,
    keyword_symbol: str,
    capability_symbol: str,
    contract_effect_symbol: str,
    output_type_symbol: str,
    version_symbol: str,
    capability_only: bool,
) -> list[str]:
    facts = [
        f"acceptedFamily({family_symbol})",
        f"acceptedLowering({lowering_symbol})",
        f"loweringAllowsFamily({lowering_symbol}, {family_symbol})",
        f"constructCandidate({construct_symbol})",
        f"constructFamily({construct_symbol}, {family_symbol})",
        f"constructKeyword({construct_symbol}, {keyword_symbol})",
        f"constructLowering({construct_symbol}, {lowering_symbol})",
        f"noKeywordConflict({construct_symbol})",
        f"noHiddenRuntime({construct_symbol})",
        f"noDirectFactWrite({construct_symbol})",
        f"lockedConstructVersion({construct_symbol}, {version_symbol})",
        f"requiresInterface({construct_symbol}, capabilityInterface({capability_symbol}))",
        f"providesInterface(capabilityInterface({capability_symbol}))",
        f"constructTargetCapability({construct_symbol}, {capability_symbol})",
        (
            f"constructEffectContract({construct_symbol}, {contract_effect_symbol}, "
            f"{output_type_symbol}, {version_symbol})"
        ),
        f"effectRequiresCapability({contract_effect_symbol}, {capability_symbol})",
    ]
    if capability_only:
        facts.insert(4, f"capabilityOnlyConstruct({construct_symbol})")
    return facts


def print_search(title: str, facts: list[str], target: str) -> None:
    print(f"--- {title}")
    print("search [1] in WHIPPLESCRIPT-GENERATED-PACKAGE-CONSTRUCT-GRAMMAR :")
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
    parser.add_argument("report", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    verifier_catalog = load_platform_construct_catalog(root, args.platform_catalog)
    package_contract = PACKAGE_BRIDGE.load_package_contract(
        root,
        verifier_catalog,
        args.report,
    )
    registry = package_contract["contract_registry"]
    symbols = PACKAGE_BRIDGE.SymbolTable()

    effect_contracts = registry.get("effect_contracts", [])
    if not isinstance(effect_contracts, list):
        raise SystemExit("package_contract.contract_registry.effect_contracts must be an array")
    effect_contract_ids = {
        PACKAGE_BRIDGE.require_string(contract, "id", "effect contract")
        for contract in effect_contracts
        if isinstance(contract, dict)
    }
    constructs = registry.get("constructs", [])
    if not isinstance(constructs, list):
        raise SystemExit("package_contract.contract_registry.constructs must be an array")

    searches: list[tuple[str, list[str], str]] = []
    for construct in constructs:
        if not isinstance(construct, dict):
            raise SystemExit("construct registry entries must be objects")
        construct_id = construct_string(construct, "id", "construct")
        label = f"construct {construct_id}"
        family = construct_string(construct, "construct_family", label)
        lowering = construct_string(construct, "lowering_target", label)
        family_symbol = FAMILY.get(family)
        lowering_symbol = LOWERING.get(lowering)
        if family_symbol is None or lowering_symbol is None:
            raise SystemExit(
                f"{label} uses unsupported family/lowering pair "
                f"{family!r}/{lowering!r}"
            )
        if family != "effect_operation" or lowering != "capability_call":
            raise SystemExit(
                "generated construct-grammar bridge currently supports only "
                f"effect_operation/capability_call, got {family!r}/{lowering!r}"
            )
        capability = capability_requirement(construct, label)
        capability_only = has_only_capability_requirements(construct, capability)
        if capability not in effect_contract_ids:
            raise SystemExit(
                f"{label} target_capability {capability!r} does not match "
                "an effect contract"
            )
        output_type = effect_handle_type(construct, label)
        version = construct_string(construct, "version", label)
        construct_symbol = symbols.symbol("ConstructId", "construct", construct_id)
        keyword_symbol = symbols.symbol(
            "Keyword",
            "keyword",
            construct_string(construct, "keyword", label),
        )
        capability_symbol = symbols.symbol("CapabilityId", "cap", capability)
        contract_effect_symbol = symbols.symbol("EffectId", "contractEffect", capability)
        use_effect_symbol = symbols.symbol("EffectId", "useEffect", f"use:{construct_id}")
        output_type_symbol = symbols.symbol("TypeId", "type", output_type)
        version_symbol = symbols.symbol("ContractVersion", "version", version)
        facts = construct_acceptance_facts(
            construct_symbol,
            family_symbol,
            lowering_symbol,
            keyword_symbol,
            capability_symbol,
            contract_effect_symbol,
            output_type_symbol,
            version_symbol,
            capability_only,
        )
        searches.append((
            f"Generated construct grammar acceptance for {construct_id}.",
            facts,
            (
                f"acceptedConstruct({construct_symbol})\n  "
                f"acceptedConstructContract({construct_symbol}, "
                f"{contract_effect_symbol}, {output_type_symbol}, "
                f"{capability_symbol}, {version_symbol})\n  "
                f"providesInterface(effectHandleInterface({output_type_symbol}))"
            ),
        ))
        searches.append((
            f"Generated construct grammar source lowering for {construct_id}.",
            facts + [f"constructUse({construct_symbol}, {use_effect_symbol})"],
            (
                f"graph(g1, {use_effect_symbol})\n  "
                f"loweredConstructEffect({use_effect_symbol}, {construct_symbol}, "
                f"{capability_symbol}, {output_type_symbol}, {version_symbol})\n  "
                f"requiredCapability({use_effect_symbol}, {capability_symbol})"
            ),
        ))

    print(f"load {root / 'models/maude/kernel.maude'}")
    print(f"load {root / 'models/maude/construct-grammar.maude'}")
    print()
    print("mod WHIPPLESCRIPT-GENERATED-PACKAGE-CONSTRUCT-GRAMMAR is")
    print("  including WHIPPLESCRIPT-CONSTRUCT-GRAMMAR .")
    for line in symbols.emit_ops():
        print(line)
    print("endm")
    print()
    print("--- Generated from whip package check package_contract constructs.")
    for title, facts, target in searches:
        print_search(title, facts, target)


if __name__ == "__main__":
    main()
