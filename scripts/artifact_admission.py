"""Shared artifact-admission checks for generated checker bridge scripts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def expected_platform_version(root: Path) -> str:
    cargo_toml = root / "Cargo.toml"
    in_workspace_package = False
    for line in cargo_toml.read_text().splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_workspace_package = line == "[workspace.package]"
            continue
        if in_workspace_package and line.startswith("version = "):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit(f"{cargo_toml} did not declare [workspace.package].version")


def validate_empty_diagnostics(value: dict[str, Any], field: str, label: str) -> None:
    diagnostics = value.get(field)
    if not isinstance(diagnostics, list):
        raise SystemExit(f"{label}.{field} must be an array")
    if diagnostics:
        raise SystemExit(
            f"{label}.{field} must be empty for verified artifact admission"
        )


def is_sha256_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        ch in "0123456789abcdef" for ch in value
    )


def validate_array_field(value: dict[str, Any], field: str, label: str) -> list[Any]:
    result = value.get(field)
    if not isinstance(result, list):
        raise SystemExit(f"{label}.{field} must be an array")
    return result


def validate_schema_field(value: dict[str, Any], expected_schema: str, label: str) -> None:
    schema = value.get("schema")
    if schema != expected_schema:
        raise SystemExit(f"{label}.schema must be {expected_schema!r}, got {schema!r}")


def validate_package_schema_type_name(name: str, label: str) -> None:
    if name not in {
        "json",
        "any",
        "string",
        "int",
        "integer",
        "float",
        "number",
        "bool",
        "boolean",
        "null",
    }:
        raise SystemExit(f"{label} uses unsupported package type {name!r}")


def validate_package_schema_shape_value(value: Any, label: str, depth: int) -> None:
    if depth > 32:
        raise SystemExit(f"{label} exceeded package schema recursion limit")
    if isinstance(value, str):
        validate_package_schema_type_name(value, label)
        return
    if isinstance(value, dict):
        for field, field_schema in value.items():
            if not field.strip():
                raise SystemExit(f"{label} contains an empty field name")
            validate_package_schema_shape_value(field_schema, f"{label}.{field}", depth + 1)
        return
    if isinstance(value, list):
        if len(value) != 1:
            raise SystemExit(f"{label} uses unsupported package tuple schema")
        validate_package_schema_shape_value(value[0], f"{label}[]", depth + 1)
        return
    raise SystemExit(
        f"{label} uses unsupported package schema fragment "
        f"{json.dumps(value, sort_keys=True)}"
    )


def validate_package_schema_fragment(schema: str, label: str) -> None:
    try:
        fragment = json.loads(schema)
    except Exception:
        validate_package_schema_type_name(schema, label)
        return
    validate_package_schema_shape_value(fragment, label, 1)


def validate_contract_registry_schema_fragments(
    registry: dict[str, Any],
    label: str,
) -> None:
    package_library_ids = {
        library["id"]
        for library in registry.get("libraries", [])
        if isinstance(library, dict)
        and isinstance(library.get("id"), str)
        and not library.get("standard", False)
        and library.get("version") != "unlocked"
    }
    contracts = validate_array_field(registry, "effect_contracts", label)
    for index, contract in enumerate(contracts):
        contract_label = f"{label}.effect_contracts[{index}]"
        if not isinstance(contract, dict):
            raise SystemExit(f"{contract_label} must be an object")
        if contract.get("library_id") not in package_library_ids:
            continue
        for field in ["input_schema", "output_schema"]:
            schema = contract.get(field)
            if schema is None:
                continue
            if not isinstance(schema, str):
                raise SystemExit(f"{contract_label}.{field} must be a string or null")
            validate_package_schema_fragment(schema, f"{contract_label}.{field}")


def package_schema_top_level_object_fields(schema: str) -> set[str] | None:
    try:
        fragment = json.loads(schema)
    except Exception:
        return None
    if isinstance(fragment, dict):
        return set(fragment.keys())
    return None


def validate_contract_registry_construct_input_fields(
    registry: dict[str, Any],
    label: str,
) -> None:
    package_library_ids = {
        library["id"]
        for library in registry.get("libraries", [])
        if isinstance(library, dict)
        and isinstance(library.get("id"), str)
        and not library.get("standard", False)
        and library.get("version") != "unlocked"
    }
    contracts = validate_array_field(registry, "effect_contracts", label)
    constructs = validate_array_field(registry, "constructs", label)
    for index, construct in enumerate(constructs):
        construct_label = f"{label}.constructs[{index}]"
        if not isinstance(construct, dict):
            raise SystemExit(f"{construct_label} must be an object")
        if construct.get("library_id") not in package_library_ids:
            continue
        if construct.get("lowering_target") != "capability_call":
            continue
        target_capability = construct.get("target_capability")
        if not isinstance(target_capability, str):
            continue
        contract = next(
            (
                candidate
                for candidate in contracts
                if isinstance(candidate, dict)
                and candidate.get("id") == target_capability
                and candidate.get("effect_kind") == "capability.call"
                and candidate.get("library_id") in package_library_ids
            ),
            None,
        )
        if contract is None:
            continue
        input_schema = contract.get("input_schema")
        if not isinstance(input_schema, str):
            continue
        input_fields = package_schema_top_level_object_fields(input_schema)
        if input_fields is None:
            continue
        construct_fields = {}
        for field in construct.get("fields", []):
            if not isinstance(field, dict) or not isinstance(field.get("name"), str):
                continue
            construct_fields[field["name"]] = field.get("required", True)
        for input_field in input_fields:
            required = construct_fields.get(input_field)
            if required is True:
                continue
            if required is False:
                raise SystemExit(
                    f"{construct_label} lowers to `{target_capability}` but target "
                    f"input_schema field `{input_field}` is optional in the construct fields"
                )
            raise SystemExit(
                f"{construct_label} lowers to `{target_capability}` but target "
                f"input_schema field `{input_field}` has no matching required construct field"
            )


def catalog_values(catalog: dict[str, Any], field: str) -> set[str]:
    values = catalog.get(field)
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str)}


def validate_catalog_string_set(
    catalog: dict[str, Any],
    field: str,
    label: str,
) -> set[str]:
    values = catalog.get(field)
    if not isinstance(values, list):
        raise SystemExit(f"{label}.{field} must be an array")
    seen = set()
    for index, value in enumerate(values):
        if not isinstance(value, str) or value == "":
            raise SystemExit(f"{label}.{field}[{index}] must be a non-empty string")
        if value in seen:
            raise SystemExit(f"{label}.{field} duplicates `{value}`")
        seen.add(value)
    return seen


def catalog_family_ids(catalog: dict[str, Any]) -> set[str]:
    families = catalog.get("families")
    if not isinstance(families, list):
        return set()
    return {
        family["id"]
        for family in families
        if isinstance(family, dict) and isinstance(family.get("id"), str)
    }


def catalog_lowerings(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lowerings = catalog.get("lowerings")
    if not isinstance(lowerings, list):
        return {}
    return {
        lowering["id"]: lowering
        for lowering in lowerings
        if isinstance(lowering, dict) and isinstance(lowering.get("id"), str)
    }


def validate_platform_construct_catalog_shape(
    catalog: dict[str, Any],
    label: str,
) -> None:
    validate_schema_field(catalog, "whipplescript.platform_construct_catalog.v0", label)
    scopes = validate_catalog_string_set(catalog, "scopes", label)
    validate_catalog_string_set(catalog, "field_kinds", label)
    interface_kinds = validate_catalog_string_set(catalog, "interface_kinds", label)
    validate_catalog_string_set(catalog, "interface_phases", label)
    validate_catalog_string_set(catalog, "interface_cardinalities", label)
    validate_catalog_string_set(catalog, "reserved_keywords", label)

    families = validate_array_field(catalog, "families", label)
    family_ids = set()
    for index, family in enumerate(families):
        family_label = f"{label}.families[{index}]"
        if not isinstance(family, dict):
            raise SystemExit(f"{family_label} must be an object")
        family_id = family.get("id")
        description = family.get("description")
        if not isinstance(family_id, str) or family_id == "":
            raise SystemExit(f"{family_label}.id must be a non-empty string")
        if family_id in family_ids:
            raise SystemExit(f"{label}.families duplicates id `{family_id}`")
        if not isinstance(description, str) or description == "":
            raise SystemExit(f"{family_label}.description must be a non-empty string")
        family_ids.add(family_id)

    lowerings = validate_array_field(catalog, "lowerings", label)
    lowering_ids = set()
    static_guarantees = {
        "deterministic",
        "contract_pinned",
        "no_runtime_inputs",
        "no_hidden_authority",
        "no_package_scheduler",
        "no_package_lifecycle",
        "no_direct_fact_write",
        "no_direct_rule_fire",
    }
    for index, lowering in enumerate(lowerings):
        lowering_label = f"{label}.lowerings[{index}]"
        if not isinstance(lowering, dict):
            raise SystemExit(f"{lowering_label} must be an object")
        lowering_id = lowering.get("id")
        if not isinstance(lowering_id, str) or lowering_id == "":
            raise SystemExit(f"{lowering_label}.id must be a non-empty string")
        if lowering_id in lowering_ids:
            raise SystemExit(f"{label}.lowerings duplicates id `{lowering_id}`")
        lowering_ids.add(lowering_id)

        compatible_families = validate_catalog_string_set(
            lowering,
            "compatible_families",
            lowering_label,
        )
        if not compatible_families:
            raise SystemExit(f"{lowering_label}.compatible_families must not be empty")
        for compatible_family in compatible_families:
            if compatible_family not in family_ids:
                raise SystemExit(
                    f"{lowering_label}.compatible_families references unknown family "
                    f"`{compatible_family}`"
                )
        if not isinstance(lowering.get("package_authorable"), bool):
            raise SystemExit(f"{lowering_label}.package_authorable must be a boolean")
        lifecycle_profiles = validate_catalog_string_set(
            lowering,
            "lifecycle_profiles",
            lowering_label,
        )
        if not lifecycle_profiles:
            raise SystemExit(f"{lowering_label}.lifecycle_profiles must not be empty")
        authority_profile = lowering.get("authority_profile")
        if authority_profile not in {
            "none",
            "capability_scoped",
            "event_admission",
            "projection_source",
        }:
            raise SystemExit(
                f"{lowering_label}.authority_profile uses unsupported value "
                f"`{authority_profile}`"
            )
        declared_static_guarantees = validate_catalog_string_set(
            lowering,
            "static_guarantees",
            lowering_label,
        )
        unknown_static_guarantees = declared_static_guarantees - static_guarantees
        if unknown_static_guarantees:
            unknown = ", ".join(sorted(unknown_static_guarantees))
            raise SystemExit(
                f"{lowering_label}.static_guarantees uses unsupported value(s): {unknown}"
            )
        missing_static_guarantees = static_guarantees - declared_static_guarantees
        if missing_static_guarantees:
            missing = ", ".join(sorted(missing_static_guarantees))
            raise SystemExit(
                f"{lowering_label}.static_guarantees is missing required value(s): {missing}"
            )
        required_scope = lowering.get("required_scope")
        if required_scope is not None and required_scope not in scopes:
            raise SystemExit(
                f"{lowering_label}.required_scope references unknown scope "
                f"`{required_scope}`"
            )
        target_capability = lowering.get("target_capability")
        if target_capability not in {
            "forbidden",
            "required_capability_call_contract",
        }:
            raise SystemExit(
                f"{lowering_label}.target_capability uses unsupported value "
                f"`{target_capability}`"
            )
        for field in ["required_interfaces", "provided_interfaces"]:
            for interface in validate_catalog_string_set(lowering, field, lowering_label):
                if interface not in interface_kinds:
                    raise SystemExit(
                        f"{lowering_label}.{field} references unknown interface "
                        f"kind `{interface}`"
                    )


_EMBEDDED_STD_CONSTRUCT_IDENTITIES: set[tuple[Any, ...]] | None = None


def embedded_std_construct_identities() -> set[tuple[Any, ...]]:
    """Identity tuples of the platform-embedded std manifest constructs.

    Python mirror of `registry_construct_is_embedded_std_copy` (cli/main.rs):
    the authorability door admits a platform-internal lowering row only when
    the construct is identical to a registration in an embedded std manifest
    (std/manifests/*.json). Fail-closed: an unreadable manifest contributes
    nothing, so the flat rejection stands.
    """
    global _EMBEDDED_STD_CONSTRUCT_IDENTITIES
    if _EMBEDDED_STD_CONSTRUCT_IDENTITIES is not None:
        return _EMBEDDED_STD_CONSTRUCT_IDENTITIES
    identities: set[tuple[Any, ...]] = set()
    manifests_dir = Path(__file__).resolve().parent.parent / "std" / "manifests"
    for path in sorted(manifests_dir.glob("*.json")):
        try:
            manifest = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        for library in manifest.get("libraries", []) or []:
            if not isinstance(library, dict):
                continue
            for construct in library.get("constructs", []) or []:
                if not isinstance(construct, dict):
                    continue
                identities.add(
                    (
                        construct.get("id"),
                        library.get("id"),
                        library.get("version"),
                        construct.get("construct_family"),
                        construct.get("keyword"),
                        construct.get("scope"),
                        construct.get("lowering_target"),
                        construct.get("target_capability"),
                    )
                )
    _EMBEDDED_STD_CONSTRUCT_IDENTITIES = identities
    return identities


def construct_is_embedded_std_copy(construct: dict[str, Any]) -> bool:
    return (
        construct.get("id"),
        construct.get("library_id"),
        construct.get("version"),
        construct.get("construct_family"),
        construct.get("keyword"),
        construct.get("scope"),
        construct.get("lowering_target"),
        construct.get("target_capability"),
    ) in embedded_std_construct_identities()


def contract_registry_package_library_ids(registry: dict[str, Any]) -> set[str]:
    return {
        library["id"]
        for library in registry.get("libraries", [])
        if isinstance(library, dict)
        and isinstance(library.get("id"), str)
        and not library.get("standard", False)
        and library.get("version") != "unlocked"
    }


def construct_declares_interface(
    construct: dict[str, Any],
    direction: str,
    kind: str,
) -> bool:
    interfaces = construct.get(direction)
    return isinstance(interfaces, list) and any(
        isinstance(interface, dict) and interface.get("kind") == kind
        for interface in interfaces
    )


def interface_signature(interface: Any) -> str:
    if not isinstance(interface, dict):
        return json.dumps(interface, sort_keys=True)
    return "|".join(
        json.dumps(interface.get(field), sort_keys=True)
        for field in ["kind", "name", "type", "phase", "cardinality"]
    )


def validate_contract_registry_package_uniqueness(
    registry: dict[str, Any],
    label: str,
) -> None:
    libraries = validate_array_field(registry, "libraries", label)
    seen_libraries = set()
    for index, library in enumerate(libraries):
        library_label = f"{label}.libraries[{index}]"
        if not isinstance(library, dict):
            raise SystemExit(f"{library_label} must be an object")
        library_id = library.get("id")
        if not isinstance(library_id, str):
            continue
        if library.get("standard", False) or library.get("version") == "unlocked":
            continue
        if library_id in seen_libraries:
            raise SystemExit(
                f"{library_label}.id duplicates locked package library `{library_id}`"
            )
        seen_libraries.add(library_id)

    package_library_ids = contract_registry_package_library_ids(registry)
    contracts = validate_array_field(registry, "effect_contracts", label)
    seen_contracts = set()
    for index, contract in enumerate(contracts):
        contract_label = f"{label}.effect_contracts[{index}]"
        if not isinstance(contract, dict):
            raise SystemExit(f"{contract_label} must be an object")
        if contract.get("library_id") not in package_library_ids:
            continue
        contract_id = contract.get("id")
        version = contract.get("version")
        if not isinstance(contract_id, str) or not isinstance(version, str):
            continue
        key = (contract_id, version)
        if key in seen_contracts:
            raise SystemExit(
                f"{contract_label} duplicates package effect contract `{contract_id}` "
                f"version `{version}`"
            )
        seen_contracts.add(key)

    constructs = validate_array_field(registry, "constructs", label)
    seen_constructs = set()
    seen_keywords = set()
    for index, construct in enumerate(constructs):
        construct_label = f"{label}.constructs[{index}]"
        if not isinstance(construct, dict):
            raise SystemExit(f"{construct_label} must be an object")
        if construct.get("library_id") not in package_library_ids:
            continue
        construct_id = construct.get("id")
        version = construct.get("version")
        if isinstance(construct_id, str) and isinstance(version, str):
            key = (construct_id, version)
            if key in seen_constructs:
                raise SystemExit(
                    f"{construct_label} duplicates package construct `{construct_id}` "
                    f"version `{version}`"
                )
            seen_constructs.add(key)

        scope = construct.get("scope")
        keyword = construct.get("keyword")
        if isinstance(scope, str) and isinstance(keyword, str):
            key = (scope, keyword)
            if key in seen_keywords:
                raise SystemExit(
                    f"{construct_label} duplicates package construct keyword `{keyword}` "
                    f"in scope `{scope}`"
                )
            seen_keywords.add(key)

        for field_name in ["fields", "requires", "provides"]:
            entries = construct.get(field_name)
            if not isinstance(entries, list):
                continue
            seen_entries = set()
            for entry_index, entry in enumerate(entries):
                if field_name == "fields":
                    signature = entry.get("name") if isinstance(entry, dict) else None
                else:
                    signature = interface_signature(entry)
                if not isinstance(signature, str):
                    continue
                if signature in seen_entries:
                    raise SystemExit(
                        f"{construct_label}.{field_name}[{entry_index}] duplicates package "
                        f"construct {field_name} entry `{signature}`"
                    )
                seen_entries.add(signature)


def validate_contract_registry_platform_vocabulary(
    registry: dict[str, Any],
    label: str,
    verifier_catalog: dict[str, Any],
) -> None:
    package_library_ids = contract_registry_package_library_ids(registry)
    family_ids = catalog_family_ids(verifier_catalog)
    lowerings = catalog_lowerings(verifier_catalog)
    scopes = catalog_values(verifier_catalog, "scopes")
    field_kinds = catalog_values(verifier_catalog, "field_kinds")
    interface_kinds = catalog_values(verifier_catalog, "interface_kinds")
    interface_phases = catalog_values(verifier_catalog, "interface_phases")
    interface_cardinalities = catalog_values(verifier_catalog, "interface_cardinalities")
    reserved_keywords = catalog_values(verifier_catalog, "reserved_keywords")

    contracts = validate_array_field(registry, "effect_contracts", label)
    package_capability_call_contract_ids = set()
    for index, contract in enumerate(contracts):
        contract_label = f"{label}.effect_contracts[{index}]"
        if not isinstance(contract, dict):
            raise SystemExit(f"{contract_label} must be an object")
        if contract.get("library_id") not in package_library_ids:
            continue
        effect_kind = contract.get("effect_kind")
        if isinstance(effect_kind, str) and effect_kind != "capability.call":
            raise SystemExit(
                f"{contract_label}.effect_kind uses unsupported package effect kind "
                f"`{effect_kind}`; expected `capability.call`"
            )
        if effect_kind == "capability.call" and isinstance(contract.get("id"), str):
            package_capability_call_contract_ids.add(contract["id"])

    for index, contract in enumerate(contracts):
        contract_label = f"{label}.effect_contracts[{index}]"
        if not isinstance(contract, dict):
            continue
        if contract.get("library_id") not in package_library_ids:
            continue
        required_capabilities = contract.get("required_capabilities")
        if not isinstance(required_capabilities, list):
            continue
        for capability in required_capabilities:
            if not isinstance(capability, str):
                continue
            if capability == "*" or capability in package_capability_call_contract_ids:
                continue
            raise SystemExit(
                f"{contract_label}.required_capabilities references `{capability}` but no "
                "matching package `capability.call` effect contract is declared"
            )

    constructs = validate_array_field(registry, "constructs", label)
    for index, construct in enumerate(constructs):
        construct_label = f"{label}.constructs[{index}]"
        if not isinstance(construct, dict):
            raise SystemExit(f"{construct_label} must be an object")
        if construct.get("library_id") not in package_library_ids:
            continue

        family = construct.get("construct_family")
        lowering_target = construct.get("lowering_target")
        scope = construct.get("scope")
        keyword = construct.get("keyword")
        if not all(isinstance(value, str) for value in [family, lowering_target, scope, keyword]):
            continue

        lowering = lowerings.get(lowering_target)
        if lowering is None:
            raise SystemExit(
                f"{construct_label}.lowering_target uses unsupported construct lowering "
                f"`{lowering_target}`"
            )
        if family not in family_ids:
            raise SystemExit(
                f"{construct_label}.construct_family uses unsupported construct family "
                f"`{family}`"
            )
        if family not in set(lowering.get("compatible_families", [])):
            raise SystemExit(
                f"{construct_label} uses lowering_target `{lowering_target}` incompatible "
                f"with construct_family `{family}`"
            )
        if lowering.get("package_authorable") is not True and not construct_is_embedded_std_copy(
            construct
        ):
            raise SystemExit(
                f"{construct_label}.lowering_target `{lowering_target}` is platform-internal "
                "and cannot be used by package constructs "
                "(only platform-embedded std manifests may use internal lowerings)"
            )
        required_scope = lowering.get("required_scope")
        if isinstance(required_scope, str) and scope != required_scope:
            raise SystemExit(
                f"{construct_label}.scope `{scope}` is unsupported for lowering_target "
                f"`{lowering_target}`; expected `{required_scope}`"
            )
        if scope not in scopes:
            raise SystemExit(
                f"{construct_label}.scope uses unsupported construct scope `{scope}`"
            )
        if keyword in reserved_keywords:
            raise SystemExit(
                f"{construct_label}.keyword uses reserved construct keyword `{keyword}`"
            )

        fields = construct.get("fields")
        if isinstance(fields, list):
            for field_index, field in enumerate(fields):
                if not isinstance(field, dict):
                    continue
                kind = field.get("kind")
                if isinstance(kind, str) and kind not in field_kinds:
                    raise SystemExit(
                        f"{construct_label}.fields[{field_index}].kind uses unsupported "
                        f"construct field kind `{kind}`"
                    )

        for direction in ["requires", "provides"]:
            interfaces = construct.get(direction)
            if not isinstance(interfaces, list):
                continue
            for interface_index, interface in enumerate(interfaces):
                if not isinstance(interface, dict):
                    continue
                interface_label = f"{construct_label}.{direction}[{interface_index}]"
                kind = interface.get("kind")
                if isinstance(kind, str) and kind not in interface_kinds:
                    raise SystemExit(
                        f"{interface_label}.kind uses unsupported construct interface kind "
                        f"`{kind}`"
                    )
                phase = interface.get("phase")
                if isinstance(phase, str) and phase not in interface_phases:
                    raise SystemExit(
                        f"{interface_label}.phase uses unsupported construct interface phase "
                        f"`{phase}`"
                    )
                cardinality = interface.get("cardinality")
                if isinstance(cardinality, str) and cardinality not in interface_cardinalities:
                    raise SystemExit(
                        f"{interface_label}.cardinality uses unsupported construct interface "
                        f"cardinality `{cardinality}`"
                    )
                if kind == "Capability" and not isinstance(interface.get("name"), str):
                    raise SystemExit(f"{interface_label} Capability interface must declare `name`")

        required_interfaces = lowering.get("required_interfaces")
        if isinstance(required_interfaces, list):
            for kind in required_interfaces:
                if isinstance(kind, str) and not construct_declares_interface(
                    construct, "requires", kind
                ):
                    raise SystemExit(
                        f"{construct_label} uses lowering_target `{lowering_target}` but "
                        f"declares no required `{kind}` interface"
                    )
        provided_interfaces = lowering.get("provided_interfaces")
        if isinstance(provided_interfaces, list):
            for kind in provided_interfaces:
                if isinstance(kind, str) and not construct_declares_interface(
                    construct, "provides", kind
                ):
                    raise SystemExit(
                        f"{construct_label} uses lowering_target `{lowering_target}` but "
                        f"declares no provided `{kind}` interface"
                    )
        if lowering.get("target_capability") == "required_capability_call_contract":
            target_capability = construct.get("target_capability")
            if not isinstance(target_capability, str):
                raise SystemExit(
                    f"{construct_label} uses lowering_target `{lowering_target}` but has no "
                    "target_capability"
                )
            if target_capability not in package_capability_call_contract_ids:
                raise SystemExit(
                    f"{construct_label} target_capability `{target_capability}` has no "
                    "matching package `capability.call` effect contract"
                )
            requires = construct.get("requires")
            if not (
                isinstance(requires, list)
                and any(
                    isinstance(interface, dict)
                    and interface.get("kind") == "Capability"
                    and interface.get("name") == target_capability
                    for interface in requires
                )
            ):
                raise SystemExit(
                    f"{construct_label} uses lowering_target `{lowering_target}` to "
                    f"`{target_capability}` but declares no required Capability interface "
                    f"named `{target_capability}`"
                )


def validate_contract_registry_shape(
    registry: Any,
    label: str,
) -> None:
    if not isinstance(registry, dict):
        raise SystemExit(f"{label} must be an object")
    validate_schema_field(registry, "whipplescript.contract_registry.v0", label)
    for field in ["libraries", "constructs", "effect_contracts", "diagnostics"]:
        validate_array_field(registry, field, label)
    validate_contract_registry_schema_fragments(registry, label)
    validate_contract_registry_package_uniqueness(registry, label)
    validate_contract_registry_construct_input_fields(registry, label)


def validate_package_contract_spine(
    package_contract: Any,
    label: str,
) -> dict[str, Any]:
    if not isinstance(package_contract, dict):
        raise SystemExit(f"{label} must be an object")
    validate_schema_field(package_contract, "whipplescript.package_contract.v0", label)
    package_contract_digest = package_contract.get("package_contract_digest")
    if not is_sha256_digest(package_contract_digest):
        raise SystemExit(
            f"{label}.package_contract_digest must be a "
            "64-character lowercase hex digest"
        )
    package_lock_digest = package_contract.get("package_lock_digest")
    if not is_sha256_digest(package_lock_digest):
        raise SystemExit(
            f"{label}.package_lock_digest must be a "
            "64-character lowercase hex digest"
        )
    validate_array_field(package_contract, "manifests", label)
    embedded_registry = package_contract.get("contract_registry")
    if not isinstance(embedded_registry, dict):
        raise SystemExit(f"{label}.contract_registry must be an object")
    validate_contract_registry_shape(embedded_registry, f"{label}.contract_registry")
    return embedded_registry


def load_platform_construct_catalog(
    root: Path,
    catalog_path: Path | None,
) -> dict[str, Any]:
    path = catalog_path
    if path is None:
        import os

        env_path = os.environ.get("WHIPPLESCRIPT_PLATFORM_CATALOG_PATH")
        if env_path:
            path = Path(env_path)
    if path is None:
        raise SystemExit(
            "WHIPPLESCRIPT_PLATFORM_CATALOG_PATH is required for verifier "
            "platform catalog admission; generate it with `whip package catalog`"
        )
    if not path.is_absolute():
        path = root / path
    try:
        catalog = json.loads(path.read_text())
    except Exception as exc:
        raise SystemExit(
            f"failed to read verifier platform catalog from {path}: {exc}"
        )
    if not isinstance(catalog, dict):
        raise SystemExit(f"verifier platform catalog {path} must be an object")
    validate_platform_construct_catalog_shape(catalog, f"verifier platform catalog {path}")
    return catalog


def validate_package_contract_platform(
    root: Path,
    verifier_catalog: dict[str, Any],
    package_contract: dict[str, Any],
    label: str,
) -> None:
    expected_version = expected_platform_version(root)
    platform_version = package_contract.get("platform_version")
    if platform_version != expected_version:
        raise SystemExit(
            f"{label}.platform_version must match verifier platform version "
            f"{expected_version!r}, got {platform_version!r}"
        )
    catalog = package_contract.get("platform_construct_catalog")
    if catalog != verifier_catalog:
        raise SystemExit(
            f"{label}.platform_construct_catalog must match verifier platform catalog"
        )
    embedded_registry = package_contract.get("contract_registry")
    if not isinstance(embedded_registry, dict):
        raise SystemExit(f"{label}.contract_registry must be an object")
    validate_contract_registry_platform_vocabulary(
        embedded_registry,
        f"{label}.contract_registry",
        verifier_catalog,
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


def stable_hash_hex(value: str) -> str:
    # Mirrors the Rust stable_hash: SHA-256 truncated to 128 bits (the
    # FNV-collision hardening swap). Extend every mirror together.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def is_stable_digest(value: str) -> bool:
    return len(value) == 32 and all(ch in "0123456789abcdef" for ch in value)


def required_string(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str):
        raise SystemExit(f"{label}.{field} must be a string")
    return result


def require_string(value: dict[str, Any], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise SystemExit(f"{label}.{key} must be a non-empty string")
    return item


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


LOWERING_CLASS = {
    "metadata": "metadataLowering",
    "metadata_only": "metadataLowering",
    "capability_call": "capabilityCall",
    "typed_effect_call": "typedEffectCall",
    "resource_effect": "resourceEffectLowering",
    "core_effect": "coreEffectLowering",
    "signal_emit": "eventEmitLowering",
    "signal_source": "eventSourceLowering",
    "schedule_emitter": "scheduleEmitterLowering",
    "projection_view": "projectionViewLowering",
    "assertion_check": "assertionCheckLowering",
    "rule_template": "ruleTemplateLowering",
}


STATIC_GUARANTEE_FACTS = {
    "deterministic": "classDeterministic",
    "contract_pinned": "classContractPinned",
    "no_runtime_inputs": "classNoRuntimeInputs",
    "no_hidden_authority": "classNoHiddenAuthority",
    "no_package_scheduler": "classNoPackageScheduler",
    "no_package_lifecycle": "classNoPackageLifecycle",
    "no_direct_fact_write": "classNoDirectFactWrite",
    "no_direct_rule_fire": "classNoDirectRuleFire",
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
