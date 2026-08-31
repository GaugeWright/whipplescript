#!/usr/bin/env python3
"""Lower a platform construct catalog into Maude lifecycle obligations."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from artifact_admission import (
    LOWERING_CLASS,
    STATIC_GUARANTEE_FACTS,
    SymbolTable,
    load_platform_construct_catalog,
    require_string,
)


CONSTRUCT_FAMILY = {
    "effect_operation": "effectOperation",
    "effect_contract": "effectContract",
    "declaration_block": "declarationBlock",
    "rule": "ruleConstruct",
    "assertion": "assertionConstruct",
    "signal_source": "eventSourceConstruct",
    "projection_read": "projectionReadConstruct",
}


def string_array(value: dict[str, Any], key: str, label: str) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list):
        raise SystemExit(f"{label}.{key} must be an array")
    result: list[str] = []
    for index, element in enumerate(item):
        if not isinstance(element, str) or not element:
            raise SystemExit(f"{label}.{key}[{index}] must be a non-empty string")
        result.append(element)
    return result


def maude_lowering_class(symbols: SymbolTable, lowering_class: str) -> str:
    return LOWERING_CLASS.get(lowering_class) or symbols.symbol(
        "LoweringClass",
        "lowering",
        lowering_class,
    )


def maude_construct_family(symbols: SymbolTable, construct_family: str) -> str:
    return CONSTRUCT_FAMILY.get(construct_family) or symbols.symbol(
        "ConstructFamily",
        "family",
        construct_family,
    )


def lowering_class_authority_facts(
    lowering: dict[str, Any],
    lowering_symbol: str,
) -> list[str]:
    authority_profile = require_string(lowering, "authority_profile", "lowering")
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
        "platform catalog bridge has unsupported lifecycle authority "
        f"profile {authority_profile!r} for lowering class "
        f"{lowering.get('id')!r}"
    )


def lowering_class_catalog_facts(
    symbols: SymbolTable,
    lowering: dict[str, Any],
) -> tuple[str, list[str]]:
    lowering_id = require_string(lowering, "id", "lowering")
    lowering_symbol = maude_lowering_class(symbols, lowering_id)
    facts = [f"classRegistered({lowering_symbol})"]
    for family in string_array(lowering, "compatible_families", f"lowering {lowering_id}"):
        family_symbol = maude_construct_family(symbols, family)
        facts.append(f"classAllowsFamily({lowering_symbol}, {family_symbol})")
    for guarantee in string_array(lowering, "static_guarantees", f"lowering {lowering_id}"):
        predicate = STATIC_GUARANTEE_FACTS.get(guarantee)
        if predicate is None:
            raise SystemExit(
                "platform catalog bridge has unsupported static guarantee "
                f"{guarantee!r} for lowering class {lowering_id!r}"
            )
        facts.append(f"{predicate}({lowering_symbol})")
    facts.extend(lowering_class_authority_facts(lowering, lowering_symbol))
    return lowering_symbol, facts


def print_search(title: str, facts: list[str], target: str) -> None:
    print(f"--- {title}")
    print("search [1] in WHIPPLESCRIPT-GENERATED-PLATFORM-CATALOG :")
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
        required=True,
        help="compiler-emitted platform catalog from `whip package catalog`",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    catalog = load_platform_construct_catalog(root, args.platform_catalog)
    lowerings = catalog.get("lowerings")
    if not isinstance(lowerings, list):
        raise SystemExit("platform catalog lowerings must be an array")

    symbols = SymbolTable()
    searches: list[tuple[str, list[str], str]] = []
    for lowering in lowerings:
        if not isinstance(lowering, dict):
            raise SystemExit("platform catalog lowerings entries must be objects")
        lowering_id = require_string(lowering, "id", "lowering")
        lowering_symbol, facts = lowering_class_catalog_facts(symbols, lowering)
        searches.append((
            f"Generated platform catalog lifecycle profile for {lowering_id}.",
            facts,
            f"catalogLoweringAccepted({lowering_symbol})",
        ))

    print(f"load {root / 'models/maude/kernel.maude'}")
    print(f"load {root / 'models/maude/construct-grammar.maude'}")
    print(f"load {root / 'models/maude/construct-graph.maude'}")
    print(f"load {root / 'models/maude/construct-lowering.maude'}")
    print(f"load {root / 'models/maude/lowering-runtime-handoff.maude'}")
    print(f"load {root / 'models/maude/lowering-class-lifecycle.maude'}")
    print()
    print("mod WHIPPLESCRIPT-GENERATED-PLATFORM-CATALOG is")
    print("  including WHIPPLESCRIPT-LOWERING-CLASS-LIFECYCLE .")
    print("  op catalogLoweringAccepted : LoweringClass -> Cfg .")
    print("  var L : LoweringClass .")
    print("  rl [accept-generated-catalog-lowering] :")
    print("    classRegistered(L)")
    print("    classStaticSafetyOk(L)")
    print("    classAuthorityOk(L)")
    print("    =>")
    print("    catalogLoweringAccepted(L) .")
    for line in symbols.emit_ops():
        print(line)
    print("endm")
    print()
    print("--- Generated from whip package catalog platform lowerings.")
    for title, facts, target in searches:
        print_search(title, facts, target)


if __name__ == "__main__":
    main()
