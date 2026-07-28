//! Package registry parse + validation core (S7 Step 3 lift).
//!
//! The pure, filesystem-free half of package-manifest loading: parse a manifest
//! JSON into a `PackageManifest`, structurally validate it (grammar, capability
//! and provider contracts, contract-registry platform vocabulary, embedded-copy
//! door), and derive its cross-package contract registry. Lifted out of the CLI
//! binary so the wasm-kernel host can run it (DR-0025 M7); it depends only on the
//! leaf `whipplescript-core` crate plus the kernel's own `exec_http::sha256_hex`.
//!
//! The filesystem-coupled DR-0025 `@tool` source attestation stays in the CLI
//! (`attest_manifest_workflow_tools`), run as a separate pass right after this
//! parse; the embedded std manifest bytes (`EMBEDDED_STD_MANIFESTS`) also stay in
//! the CLI and are threaded in as the `embedded` / `embedded_manifests`
//! parameters here (`std` bytes stay out of wasm).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::exec_http::sha256_hex;
use whipplescript_core::json::{
    optional_json_string, optional_json_string_any, optional_json_string_array,
    quoted_platform_values, require_json_array_field, required_json_string,
};
use whipplescript_core::{
    ConstructField, ConstructGrammar, ConstructGrammarClause, ConstructGrammarPayloadField,
    ConstructGrammarSlot, ConstructInterface, ConstructRegistration,
    ConstructTargetCapabilityPolicy, ContractRegistry, EffectContract, LibraryRegistration,
    PlatformConstructLowering, TypedOutputValidation, CONSTRUCT_FAMILY_EFFECT_OPERATION,
    CONSTRUCT_GRAMMAR_BINDING_MODES, CONSTRUCT_GRAMMAR_CLAUSE_CONNECTIVES,
    CONSTRUCT_GRAMMAR_CLAUSE_KINDS, CONSTRUCT_GRAMMAR_CONNECTIVES,
    CONSTRUCT_GRAMMAR_SHAPE_DECLARATION_BLOCK, CONSTRUCT_GRAMMAR_SHAPE_EFFECT_OPERATION,
    CONSTRUCT_GRAMMAR_SLOT_KINDS, CONSTRUCT_INTERFACE_CAPABILITY,
    CONSTRUCT_INTERFACE_CARDINALITY_EXACTLY_ONE, CONSTRUCT_INTERFACE_PHASE_COMPILE_RUNTIME,
    CONSTRUCT_LOWERING_CAPABILITY_CALL, CONSTRUCT_LOWERING_METADATA_ONLY,
    PLATFORM_CONSTRUCT_CATALOG,
};

pub fn verify_contract_registry_platform_vocabulary(
    registry: &Value,
    label: &str,
    embedded_manifests: &[PackageManifest],
) -> Result<(), String> {
    let package_library_ids = report_package_library_ids(registry);
    let contracts = require_json_array_field(registry, "effect_contracts", label)?;
    let mut package_capability_call_contract_ids = BTreeSet::new();
    for (index, contract) in contracts.iter().enumerate() {
        let contract_label = format!("{label}.effect_contracts[{index}]");
        if !contract.is_object() {
            return Err(format!("{contract_label} must be an object"));
        }
        if !contract
            .get("library_id")
            .and_then(Value::as_str)
            .is_some_and(|library_id| package_library_ids.contains(library_id))
        {
            continue;
        }
        let Some(effect_kind) = contract.get("effect_kind").and_then(Value::as_str) else {
            continue;
        };
        if effect_kind != "capability.call" {
            return Err(format!(
                "{contract_label}.effect_kind uses unsupported package effect kind `{effect_kind}`; expected `capability.call`"
            ));
        }
        if let Some(id) = contract.get("id").and_then(Value::as_str) {
            package_capability_call_contract_ids.insert(id.to_owned());
        }
    }
    for (index, contract) in contracts.iter().enumerate() {
        let contract_label = format!("{label}.effect_contracts[{index}]");
        if !contract
            .get("library_id")
            .and_then(Value::as_str)
            .is_some_and(|library_id| package_library_ids.contains(library_id))
        {
            continue;
        }
        for capability in contract
            .get("required_capabilities")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if capability == "*" || package_capability_call_contract_ids.contains(capability) {
                continue;
            }
            return Err(format!(
                "{contract_label}.required_capabilities references `{capability}` but no matching package `capability.call` effect contract is declared"
            ));
        }
    }

    let constructs = require_json_array_field(registry, "constructs", label)?;
    for (index, construct) in constructs.iter().enumerate() {
        let construct_label = format!("{label}.constructs[{index}]");
        if !construct.is_object() {
            return Err(format!("{construct_label} must be an object"));
        }
        if !construct
            .get("library_id")
            .and_then(Value::as_str)
            .is_some_and(|library_id| package_library_ids.contains(library_id))
        {
            continue;
        }
        let Some(family) = construct.get("construct_family").and_then(Value::as_str) else {
            continue;
        };
        let Some(lowering_target) = construct.get("lowering_target").and_then(Value::as_str) else {
            continue;
        };
        let Some(scope) = construct.get("scope").and_then(Value::as_str) else {
            continue;
        };
        let Some(keyword) = construct.get("keyword").and_then(Value::as_str) else {
            continue;
        };
        let Some(lowering) = PLATFORM_CONSTRUCT_CATALOG.lowering(lowering_target) else {
            return Err(format!(
                "{construct_label}.lowering_target uses unsupported construct lowering `{lowering_target}`"
            ));
        };
        if PLATFORM_CONSTRUCT_CATALOG.family(family).is_none() {
            return Err(format!(
                "{construct_label}.construct_family uses unsupported construct family `{family}`"
            ));
        }
        if !lowering.compatible_families.contains(&family) {
            return Err(format!(
                "{construct_label} uses lowering_target `{lowering_target}` incompatible with construct_family `{family}`"
            ));
        }
        let library_id = construct
            .get("library_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !lowering.package_authorable
            && !registry_construct_is_embedded_std_copy(construct, embedded_manifests)
            && !privilege_tuple_authorizes_internal_lowering(
                library_id,
                keyword,
                family,
                scope,
                lowering_target,
            )
        {
            return Err(format!(
                "{construct_label}.lowering_target `{lowering_target}` is platform-internal and cannot be used by package constructs (only platform-embedded std manifests or platform-catalog privilege tuples may use internal lowerings)"
            ));
        }
        if let Some(required_scope) = lowering.required_scope {
            if scope != required_scope {
                return Err(format!(
                    "{construct_label}.scope `{scope}` is unsupported for lowering_target `{lowering_target}`; expected `{required_scope}`"
                ));
            }
        }
        if !PLATFORM_CONSTRUCT_CATALOG.contains_scope(scope) {
            return Err(format!(
                "{construct_label}.scope uses unsupported construct scope `{scope}`"
            ));
        }
        if let Some(error) = reserved_keyword_privilege_error(
            construct
                .get("library_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            keyword,
            family,
            scope,
            lowering_target,
        ) {
            return Err(format!("{construct_label}.keyword {error}"));
        }
        for (field_index, field) in construct
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let field_label = format!("{construct_label}.fields[{field_index}]");
            let Some(kind) = field.get("kind").and_then(Value::as_str) else {
                continue;
            };
            if !PLATFORM_CONSTRUCT_CATALOG.contains_field_kind(kind) {
                return Err(format!(
                    "{field_label}.kind uses unsupported construct field kind `{kind}`"
                ));
            }
        }
        for direction in ["requires", "provides"] {
            for (interface_index, interface) in construct
                .get(direction)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let interface_label = format!("{construct_label}.{direction}[{interface_index}]");
                verify_contract_registry_construct_interface_vocabulary(
                    interface,
                    &interface_label,
                )?;
            }
        }
        verify_contract_registry_construct_lowering_interfaces(
            construct,
            lowering,
            &package_capability_call_contract_ids,
            &construct_label,
        )?;
    }
    Ok(())
}

/// Authorability door, privilege-tuple leg (std.coord slice 4; M5
/// "Authorability door"): a platform-catalog reserved-keyword privilege tuple
/// whose `lowering_target` is a non-package-authorable class ALSO authorizes
/// that class — for exactly that (library, keyword, family, scope, lowering)
/// tuple and nothing else. The catalog is compiled into the platform, so a
/// third party can never mint a tuple; a non-privileged manifest carrying the
/// same construct row is still rejected. Second leg alongside the S6d-5
/// embedded-copy key (`manifest_is_embedded_copy`); modeled in
/// models/maude/std-construct-authorization.maude (`[door-privileged]`, with
/// keyword- and library-coordinate bite fixtures).
pub fn privilege_tuple_authorizes_internal_lowering(
    library_id: &str,
    keyword: &str,
    construct_family: &str,
    scope: &str,
    lowering_target: &str,
) -> bool {
    PLATFORM_CONSTRUCT_CATALOG
        .reserved_keyword_privilege(
            library_id,
            keyword,
            construct_family,
            scope,
            lowering_target,
        )
        .is_some()
}

pub fn reserved_keyword_privilege_error(
    library_id: &str,
    keyword: &str,
    construct_family: &str,
    scope: &str,
    lowering_target: &str,
) -> Option<String> {
    if !PLATFORM_CONSTRUCT_CATALOG.contains_reserved_keyword(keyword) {
        return None;
    }
    if PLATFORM_CONSTRUCT_CATALOG
        .reserved_keyword_privilege(
            library_id,
            keyword,
            construct_family,
            scope,
            lowering_target,
        )
        .is_some()
    {
        return None;
    }
    Some(format!(
        "uses reserved construct keyword `{keyword}` without platform catalog authorization for library `{library_id}` as {scope} {construct_family} lowering `{lowering_target}`"
    ))
}

pub fn verify_contract_registry_construct_interface_vocabulary(
    interface: &Value,
    label: &str,
) -> Result<(), String> {
    let Some(kind) = interface.get("kind").and_then(Value::as_str) else {
        return Ok(());
    };
    if !PLATFORM_CONSTRUCT_CATALOG.contains_interface_kind(kind) {
        return Err(format!(
            "{label}.kind uses unsupported construct interface kind `{kind}`"
        ));
    }
    let Some(phase) = interface.get("phase").and_then(Value::as_str) else {
        return Ok(());
    };
    if !PLATFORM_CONSTRUCT_CATALOG.contains_interface_phase(phase) {
        return Err(format!(
            "{label}.phase uses unsupported construct interface phase `{phase}`"
        ));
    }
    let Some(cardinality) = interface.get("cardinality").and_then(Value::as_str) else {
        return Ok(());
    };
    if !PLATFORM_CONSTRUCT_CATALOG.contains_interface_cardinality(cardinality) {
        return Err(format!(
            "{label}.cardinality uses unsupported construct interface cardinality `{cardinality}`"
        ));
    }
    if kind == CONSTRUCT_INTERFACE_CAPABILITY
        && interface.get("name").and_then(Value::as_str).is_none()
    {
        return Err(format!("{label} Capability interface must declare `name`"));
    }
    Ok(())
}

pub fn verify_contract_registry_construct_lowering_interfaces(
    construct: &Value,
    lowering: &PlatformConstructLowering,
    package_capability_call_contract_ids: &BTreeSet<String>,
    label: &str,
) -> Result<(), String> {
    for kind in lowering.required_interfaces {
        if !contract_registry_construct_declares_interface(construct, "requires", kind) {
            return Err(format!(
                "{label} uses lowering_target `{}` but declares no required `{kind}` interface",
                lowering.id
            ));
        }
    }
    for kind in lowering.provided_interfaces {
        if !contract_registry_construct_declares_interface(construct, "provides", kind) {
            return Err(format!(
                "{label} uses lowering_target `{}` but declares no provided `{kind}` interface",
                lowering.id
            ));
        }
    }
    if lowering.target_capability == ConstructTargetCapabilityPolicy::RequiredCapabilityCallContract
    {
        let Some(target_capability) = construct.get("target_capability").and_then(Value::as_str)
        else {
            return Err(format!(
                "{label} uses lowering_target `{}` but has no target_capability",
                lowering.id
            ));
        };
        if !package_capability_call_contract_ids.contains(target_capability) {
            return Err(format!(
                "{label} target_capability `{target_capability}` has no matching package `capability.call` effect contract"
            ));
        }
        if !construct
            .get("requires")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|interface| {
                interface.get("kind").and_then(Value::as_str)
                    == Some(CONSTRUCT_INTERFACE_CAPABILITY)
                    && interface.get("name").and_then(Value::as_str) == Some(target_capability)
            })
        {
            return Err(format!(
                "{label} uses lowering_target `{}` to `{target_capability}` but declares no required Capability interface named `{target_capability}`",
                lowering.id
            ));
        }
    }
    // A `Forbidden` lowering (e.g. `typed_effect_call`) must NOT name a generic
    // `target_capability` the way `capability_call` does — its authority comes
    // from the typed effect contract + its required `Capability` interface, not a
    // capability-call target. (DR-0020 chain / `std.files`.)
    if lowering.target_capability == ConstructTargetCapabilityPolicy::Forbidden
        && construct
            .get("target_capability")
            .and_then(Value::as_str)
            .is_some()
    {
        return Err(format!(
            "{label} uses lowering_target `{}` which forbids a `target_capability`, but one is declared",
            lowering.id
        ));
    }
    Ok(())
}

pub fn contract_registry_construct_declares_interface(
    construct: &Value,
    direction: &str,
    kind: &str,
) -> bool {
    construct
        .get(direction)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|interface| interface.get("kind").and_then(Value::as_str) == Some(kind))
}

pub fn report_package_library_ids(registry: &Value) -> BTreeSet<String> {
    registry
        .get("libraries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|library| {
            let id = library.get("id").and_then(Value::as_str)?;
            let standard = library
                .get("standard")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let version = library.get("version").and_then(Value::as_str);
            (!standard && version != Some("unlocked")).then(|| id.to_owned())
        })
        .collect()
}

pub const PACKAGE_MANIFEST_SCHEMA: &str = "whipplescript.package_manifest.v0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageManifest {
    pub path: PathBuf,
    pub manifest_json: String,
    pub manifest_sha256: String,
    pub package_id: String,
    pub name: String,
    pub version: String,
    pub registry: ContractRegistry,
    /// `@tool` workflows this package exports for cross-package invocation
    /// (DR-0025). Derived + convergence-checked when the manifest is loaded, so a
    /// non-`@tool`/non-convergent export fails manifest validation on both the
    /// producer (`whip package`) and the consumer (`use`) side.
    pub workflow_tools: Vec<PackageWorkflowTool>,
}

/// A `@tool` workflow exported by a package (DR-0025 cross-package attestation):
/// the tool name, the resolved source path it is driven from, and the derived
/// input/output JSON schemas (canonical JSON strings) that make up its tool
/// contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageWorkflowTool {
    pub name: String,
    pub source: PathBuf,
    pub input_schema: String,
    pub output_schema: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageCapabilityContract {
    pub input_schema: Option<String>,
    pub output_schema: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageProviderContract {
    pub capability: String,
    pub provider_kind: String,
}

/// A capability-free operator-plane provider row (`"plane": "operator"`,
/// std-telemetry.md T3): configuration an operator CLI surface reads (e.g.
/// std.telemetry's `otlp` exporter defaults), never consulted by the effect
/// admission gate. A distinct type — not an `Option<String>` capability on
/// [`PackageProviderContract`] — so no admission-plane code path can reach
/// one by construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorProviderContract {
    pub id: String,
    pub provider_kind: String,
    /// The row's `config` object as raw JSON text (defaults the consuming
    /// CLI reads; env/flags override).
    pub config_json: Option<String>,
}

/// The manifest's operator-plane provider rows (the ones
/// `package_provider_contracts` deliberately skips).
pub fn package_operator_providers(
    path: &Path,
    value: &Value,
) -> Result<Vec<OperatorProviderContract>, String> {
    let mut rows = Vec::new();
    for provider in value
        .get("providers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if provider.get("plane").and_then(Value::as_str) != Some("operator") {
            continue;
        }
        rows.push(OperatorProviderContract {
            id: required_json_string(provider, "id", "provider")
                .map_err(|message| format!("{} in `{}`", message, path.display()))?,
            provider_kind: required_json_string(provider, "provider_kind", "provider")
                .map_err(|message| format!("{} in `{}`", message, path.display()))?,
            config_json: provider.get("config").map(|config| config.to_string()),
        });
    }
    Ok(rows)
}

/// Whether `raw_json` is byte-identical to a manifest in `embedded` (in
/// production, `EMBEDDED_STD_MANIFESTS`; parameterized so the authorability-
/// door privilege key is unit-testable with a synthetic manifest set). The key
/// is byte-identity of the raw manifest JSON: the manifest literally IS the
/// platform copy compiled into the binary — unforgeable by third parties, and
/// a same-name different-content file gains nothing.
///
/// The door admits `package_authorable: false` lowering classes for such a
/// copy — the embedded leg. Its second leg is the platform-catalog privilege
/// tuple (`privilege_tuple_authorizes_internal_lowering`, std.coord slice 4):
/// std.coord's embedded manifest declares four `resource_effect` constructs,
/// admitted through either leg. Third parties hold neither key.
pub fn manifest_is_embedded_copy(raw_json: &str, embedded: &[(&str, &str)]) -> bool {
    embedded
        .iter()
        .any(|(_, manifest_json)| *manifest_json == raw_json)
}

/// Whether a report contract-registry construct entry is the platform's own
/// embedded std copy: some `EMBEDDED_STD_MANIFESTS` registry registers a
/// construct with the same identity and lowering row. Report registries carry
/// merged embedded std entries rather than manifest bytes, so the manifest
/// byte-identity key cannot apply at that layer; registration identity is the
/// equivalent check there (a same-id, different-shape entry gains nothing).
pub fn registry_construct_is_embedded_std_copy(
    construct: &Value,
    embedded_manifests: &[PackageManifest],
) -> bool {
    let field = |name: &str| construct.get(name).and_then(Value::as_str);
    embedded_manifests.iter().any(|manifest| {
        manifest.registry.constructs.iter().any(|form| {
            field("id") == Some(form.id.as_str())
                && field("library_id") == Some(form.library_id.as_str())
                && field("version") == Some(form.version.as_str())
                && field("construct_family") == Some(form.construct_family.as_str())
                && field("keyword") == Some(form.keyword.as_str())
                && field("scope") == Some(form.scope.as_str())
                && field("lowering_target") == Some(form.lowering_target.as_str())
                && field("target_capability") == form.target_capability.as_deref()
        })
    })
}

/// `package_manifest_from_json` against an explicit embedded manifest set.
/// A manifest byte-identical to an embedded entry validates as privileged: the
/// authorability door admits `package_authorable: false` lowering classes for
/// the platform's own compiled-in std copies only (see
/// `manifest_is_embedded_copy`).
pub fn package_manifest_from_json_with_embedded(
    path: &Path,
    manifest_json: String,
    embedded: &[(&str, &str)],
) -> Result<PackageManifest, String> {
    let privileged = manifest_is_embedded_copy(&manifest_json, embedded);
    let value = serde_json::from_str::<Value>(&manifest_json).map_err(|error| {
        format!(
            "failed to parse package manifest `{}`: {error}",
            path.display()
        )
    })?;
    let schema = required_json_string(&value, "schema", "package manifest")?;
    if schema != PACKAGE_MANIFEST_SCHEMA {
        return Err(format!(
            "package manifest `{}` has unsupported schema `{schema}`; expected `{PACKAGE_MANIFEST_SCHEMA}`",
            path.display()
        ));
    }
    validate_package_manifest_closed_shape(path, &value)?;
    let package_id = required_json_string(&value, "package_id", "package manifest")?;
    let name = required_json_string(&value, "name", "package manifest")?;
    let version = required_json_string(&value, "version", "package manifest")?;

    validate_package_manifest_identity_uniqueness(path, &value)?;
    let capabilities = package_capability_contracts(path, &value)?;
    let providers = package_provider_contracts(path, &value)?;
    let registry = package_manifest_registry_with_privilege(
        path,
        &value,
        &name,
        &version,
        &capabilities,
        &providers,
        privileged,
    )?;
    validate_package_manifest_consistency(
        path,
        &value,
        &capabilities,
        &providers,
        &registry,
        privileged,
    )?;
    let workflow_tools = package_manifest_workflow_tool_decls(path, &value)?;

    Ok(PackageManifest {
        path: path.to_path_buf(),
        manifest_sha256: sha256_hex(manifest_json.as_bytes()),
        manifest_json,
        package_id,
        name,
        version,
        registry,
        workflow_tools,
    })
}

/// Parse the DECLARATIONS of a package's exported `@tool` workflows (DR-0025):
/// each entry's name and resolved source path, with structural validation (array
/// shape, required `name`/`source` fields, no duplicate names). This is pure — it
/// reads no source files — so it stays inside the wasm-kernel-hostable parse.
///
/// The source COMPILATION + attestation (`@tool` tag, convergence, workflow-name
/// match, derived input/output schemas) is a SEPARATE cli-only pass,
/// `attest_manifest_workflow_tools`, run right after parse at every load site (see
/// `load_package_manifest`), because it reads tool sources from disk and cannot
/// enter the kernel. Splitting it out is what makes the parse+validate core
/// filesystem-free.
pub fn package_manifest_workflow_tool_decls(
    path: &Path,
    value: &Value,
) -> Result<Vec<PackageWorkflowTool>, String> {
    let Some(entries) = value.get("workflow_tools") else {
        return Ok(Vec::new());
    };
    let entries = entries.as_array().ok_or_else(|| {
        format!(
            "package manifest `{}` field `workflow_tools` must be an array",
            path.display()
        )
    })?;
    let manifest_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tools = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in entries {
        let name = required_json_string(entry, "name", "workflow_tools entry")?;
        let source_rel = required_json_string(entry, "source", "workflow_tools entry")?;
        if !seen.insert(name.clone()) {
            return Err(format!(
                "package manifest `{}` exports workflow tool `{name}` more than once",
                path.display()
            ));
        }
        let source = manifest_dir.join(&source_rel);
        // The input/output tool schemas are derived by the attestation pass, which
        // compiles the source; the declaration carries only name + resolved path.
        tools.push(PackageWorkflowTool {
            name,
            source,
            input_schema: String::new(),
            output_schema: String::new(),
        });
    }
    Ok(tools)
}

/// `privileged` marks the platform's own embedded std copy (byte-identity with
/// an `EMBEDDED_STD_MANIFESTS` entry, computed by the caller): the
/// authorability door admits `package_authorable: false` lowering classes for
/// it and for nothing else.
pub fn validate_package_manifest_consistency(
    path: &Path,
    value: &Value,
    capabilities: &BTreeMap<String, PackageCapabilityContract>,
    providers: &[PackageProviderContract],
    registry: &ContractRegistry,
    privileged: bool,
) -> Result<(), String> {
    let declared_capabilities = capabilities.keys().cloned().collect::<BTreeSet<_>>();
    let mut provider_kinds_by_capability = BTreeMap::<String, BTreeSet<String>>::new();
    let mut problems = Vec::new();

    for provider in providers {
        provider_kinds_by_capability
            .entry(provider.capability.clone())
            .or_default()
            .insert(provider.provider_kind.clone());
        validate_declared_capability(
            path,
            &declared_capabilities,
            &provider.capability,
            &format!("provider `{}`", provider.provider_kind),
            &mut problems,
        );
    }

    for contract in &registry.effect_contracts {
        // Core effect kinds are declarable only by the platform's own embedded
        // std copies (the same privilege door as platform-internal lowerings):
        // e.g. std.coercion's `schema.coerce` contract, which mirrors the
        // parser-compiled one and merge-folds against it.
        if contract.effect_kind != "capability.call" && !privileged {
            problems.push(format!(
                "effect contract `{}` uses unsupported effect_kind `{}`; packages currently support only `capability.call`",
                contract.id, contract.effect_kind
            ));
        }
        validate_declared_capability(
            path,
            &declared_capabilities,
            &contract.id,
            &format!("effect contract `{}`", contract.id),
            &mut problems,
        );
        for capability in &contract.required_capabilities {
            validate_declared_capability(
                path,
                &declared_capabilities,
                capability,
                &format!("effect contract `{}` required_capabilities", contract.id),
                &mut problems,
            );
        }
    }

    for form in &registry.constructs {
        let family = PLATFORM_CONSTRUCT_CATALOG.family(&form.construct_family);
        let lowering = PLATFORM_CONSTRUCT_CATALOG.lowering(&form.lowering_target);
        if family.is_none() {
            problems.push(format!(
                "construct `{}` uses unsupported construct_family `{}`; expected one of {}",
                form.id,
                form.construct_family,
                quoted_platform_values(PLATFORM_CONSTRUCT_CATALOG.family_ids())
            ));
        }
        match lowering {
            Some(lowering) => {
                if family.is_some()
                    && !lowering
                        .compatible_families
                        .contains(&form.construct_family.as_str())
                {
                    let expected = quoted_platform_values(
                        PLATFORM_CONSTRUCT_CATALOG
                            .lowerings_for_family(&form.construct_family)
                            .filter(|lowering| lowering.package_authorable)
                            .map(|lowering| lowering.id),
                    );
                    if form.lowering_target == CONSTRUCT_LOWERING_CAPABILITY_CALL {
                        problems.push(format!(
                            "construct `{}` uses capability_call lowering but construct_family is `{}`; expected `{}`",
                            form.id, form.construct_family, CONSTRUCT_FAMILY_EFFECT_OPERATION
                        ));
                    } else {
                        problems.push(format!(
                            "construct `{}` is a {} but uses lowering_target `{}`; expected one of {}",
                            form.id, form.construct_family, form.lowering_target, expected
                        ));
                    }
                }
                if !lowering.package_authorable
                    && !privileged
                    && !privilege_tuple_authorizes_internal_lowering(
                        &form.library_id,
                        &form.keyword,
                        &form.construct_family,
                        &form.scope,
                        &form.lowering_target,
                    )
                {
                    problems.push(format!(
                        "construct `{}` uses platform-internal lowering_target `{}`; package constructs must use an authorable platform lowering (only platform-embedded std manifests or platform-catalog privilege tuples may use internal lowerings)",
                        form.id, form.lowering_target
                    ));
                }
                if let Some(required_scope) = lowering.required_scope {
                    if form.scope != required_scope {
                        problems.push(format!(
                            "construct `{}` uses {} lowering in unsupported scope `{}`; {} forms are currently {} only",
                            form.id,
                            lowering.id,
                            form.scope,
                            lowering.id,
                            required_scope
                        ));
                    }
                }
                match lowering.target_capability {
                    ConstructTargetCapabilityPolicy::Forbidden => {
                        if form.target_capability.is_some() {
                            problems.push(format!(
                                "construct `{}` is {} but declares target_capability",
                                form.id, lowering.id
                            ));
                        }
                    }
                    ConstructTargetCapabilityPolicy::RequiredCapabilityCallContract => {
                        let Some(target_capability) = form.target_capability.as_deref() else {
                            problems.push(format!(
                                "construct `{}` uses {} lowering but has no target_capability",
                                form.id, lowering.id
                            ));
                            continue;
                        };
                        validate_declared_capability(
                            path,
                            &declared_capabilities,
                            target_capability,
                            &format!("construct `{}` target_capability", form.id),
                            &mut problems,
                        );
                        let target_contract = registry.effect_contracts.iter().find(|contract| {
                            contract.id == target_capability
                                && contract.effect_kind == "capability.call"
                        });
                        if let Some(contract) = target_contract {
                            validate_construct_input_schema_fields(form, contract, &mut problems);
                        } else {
                            problems.push(format!(
                                "construct `{}` lowers to `{target_capability}` but no matching `capability.call` effect contract is declared",
                                form.id
                            ));
                        }
                    }
                }
            }
            None => {
                problems.push(format!(
                    "construct `{}` uses unsupported lowering_target `{}`; expected one of {}",
                    form.id,
                    form.lowering_target,
                    quoted_platform_values(
                        PLATFORM_CONSTRUCT_CATALOG
                            .lowerings
                            .iter()
                            .filter(|lowering| lowering.package_authorable)
                            .map(|lowering| lowering.id),
                    )
                ));
            }
        }
        if !PLATFORM_CONSTRUCT_CATALOG.contains_scope(&form.scope) {
            problems.push(format!(
                "construct `{}` uses unsupported scope `{}`; expected one of {}",
                form.id,
                form.scope,
                quoted_platform_values(PLATFORM_CONSTRUCT_CATALOG.scopes.iter().copied())
            ));
        }
        if let Some(error) = reserved_keyword_privilege_error(
            &form.library_id,
            &form.keyword,
            &form.construct_family,
            &form.scope,
            &form.lowering_target,
        ) {
            problems.push(format!("construct `{}` {error}", form.id));
        }
        for field in &form.fields {
            if !PLATFORM_CONSTRUCT_CATALOG.contains_field_kind(&field.kind) {
                problems.push(format!(
                    "construct `{}` field `{}` uses unsupported kind `{}`; expected one of {}",
                    form.id,
                    field.name,
                    field.kind,
                    quoted_platform_values(PLATFORM_CONSTRUCT_CATALOG.field_kinds.iter().copied())
                ));
            }
        }
        validate_construct_interface_records(path, form, &declared_capabilities, &mut problems);
        if let Some(lowering) = lowering {
            validate_construct_lowering_interfaces(form, lowering, &mut problems);
        }
    }

    for profile in value
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let profile_name = optional_json_string(profile, "name")
            .or_else(|| optional_json_string(profile, "id"))
            .unwrap_or_else(|| "<unnamed>".to_owned());
        for capability in
            optional_json_string_array(profile, "allowed_capabilities").unwrap_or_default()
        {
            validate_declared_capability(
                path,
                &declared_capabilities,
                &capability,
                &format!("profile `{profile_name}` allowed_capabilities"),
                &mut problems,
            );
        }
    }

    for binding in value
        .get("bindings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let binding_name =
            optional_json_string(binding, "id").unwrap_or_else(|| "<unnamed>".to_owned());
        let capability = match required_json_string(binding, "capability", "binding") {
            Ok(capability) => capability,
            Err(message) => {
                problems.push(format!("{message} in `{}`", path.display()));
                continue;
            }
        };
        validate_declared_capability(
            path,
            &declared_capabilities,
            &capability,
            &format!("binding `{binding_name}`"),
            &mut problems,
        );
        let provider_kind = match required_json_string(binding, "provider", "binding") {
            Ok(provider_kind) => provider_kind,
            Err(message) => {
                problems.push(format!("{message} in `{}`", path.display()));
                continue;
            }
        };
        match provider_kinds_by_capability.get(&capability) {
            Some(kinds) if kinds.contains(&provider_kind) => {}
            Some(kinds) => problems.push(format!(
                "binding `{binding_name}` in `{}` references provider `{provider_kind}` for capability `{capability}`, but declared providers for that capability are: {}",
                path.display(),
                kinds.iter()
                    .map(|kind| format!("`{kind}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            None => problems.push(format!(
                "binding `{binding_name}` in `{}` references capability `{capability}` without a provider",
                path.display()
            )),
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "package manifest `{}` has invalid package contracts:\n- {}",
            path.display(),
            problems.join("\n- ")
        ))
    }
}

pub fn validate_package_manifest_closed_shape(path: &Path, value: &Value) -> Result<(), String> {
    let mut problems = Vec::new();
    validate_manifest_object_fields(
        value,
        "package manifest",
        &[
            "schema",
            "package_id",
            "name",
            "version",
            "libraries",
            "capabilities",
            "providers",
            "profiles",
            "bindings",
            "workflow_tools",
        ],
        &mut problems,
    );
    validate_manifest_required_fields(
        value,
        "package manifest",
        &["schema", "package_id", "name", "version"],
        &mut problems,
    );
    validate_manifest_array_objects(
        value,
        "package manifest",
        "workflow_tools",
        &mut problems,
        |tool, label, problems| {
            validate_manifest_object_fields(tool, &label, &["name", "source"], problems);
            validate_manifest_required_fields(tool, &label, &["name", "source"], problems);
            validate_manifest_string_fields(tool, &label, &["name", "source"], problems);
        },
    );
    validate_manifest_string_fields(
        value,
        "package manifest",
        &["schema", "package_id", "name", "version"],
        &mut problems,
    );

    validate_manifest_array_objects(
        value,
        "package manifest",
        "libraries",
        &mut problems,
        |library, label, problems| {
            validate_manifest_object_fields(
                library,
                &label,
                &[
                    "id",
                    "version",
                    "standard",
                    "effect_contracts",
                    "effects",
                    "constructs",
                ],
                problems,
            );
            validate_manifest_required_fields(library, &label, &["id"], problems);
            validate_manifest_string_fields(library, &label, &["id", "version"], problems);
            validate_manifest_bool_fields(library, &label, &["standard"], problems);
            for field in ["effect_contracts", "effects"] {
                validate_manifest_array_objects(
                    library,
                    &label,
                    field,
                    problems,
                    |contract, label, problems| {
                        validate_manifest_object_fields(
                            contract,
                            &label,
                            &[
                                "id",
                                "effect_kind",
                                "core_effect_kind",
                                "source_forms",
                                "input_schema",
                                "output_schema",
                                "required_capabilities",
                                "provider_kinds",
                                "projected_facts",
                                "validation",
                            ],
                            problems,
                        );
                        validate_manifest_required_fields(contract, &label, &["id"], problems);
                        validate_manifest_string_fields(
                            contract,
                            &label,
                            &["id", "effect_kind", "core_effect_kind", "validation"],
                            problems,
                        );
                        validate_manifest_string_array_fields(
                            contract,
                            &label,
                            &[
                                "source_forms",
                                "required_capabilities",
                                "provider_kinds",
                                "projected_facts",
                            ],
                            problems,
                        );
                    },
                );
            }
            validate_manifest_array_objects(
                library,
                &label,
                "constructs",
                problems,
                |construct, label, problems| {
                    validate_manifest_object_fields(
                        construct,
                        &label,
                        &[
                            "id",
                            "construct_family",
                            "keyword",
                            "scope",
                            "grammar",
                            "fields",
                            "requires",
                            "provides",
                            "lowering_target",
                            "target_capability",
                        ],
                        problems,
                    );
                    validate_manifest_required_fields(
                        construct,
                        &label,
                        &["id", "construct_family", "keyword"],
                        problems,
                    );
                    validate_manifest_string_fields(
                        construct,
                        &label,
                        &[
                            "id",
                            "construct_family",
                            "keyword",
                            "scope",
                            "lowering_target",
                            "target_capability",
                        ],
                        problems,
                    );
                    validate_manifest_array_objects(
                        construct,
                        &label,
                        "fields",
                        problems,
                        |field, label, problems| {
                            validate_manifest_object_fields(
                                field,
                                &label,
                                &["name", "kind", "required"],
                                problems,
                            );
                            validate_manifest_required_fields(
                                field,
                                &label,
                                &["name", "kind"],
                                problems,
                            );
                            validate_manifest_string_fields(
                                field,
                                &label,
                                &["name", "kind"],
                                problems,
                            );
                            validate_manifest_bool_fields(field, &label, &["required"], problems);
                        },
                    );
                    if let Some(grammar) = construct.get("grammar") {
                        validate_manifest_construct_grammar_shape(
                            grammar,
                            &format!("{label}.grammar"),
                            problems,
                        );
                    }
                    for direction in ["requires", "provides"] {
                        validate_manifest_array_objects(
                            construct,
                            &label,
                            direction,
                            problems,
                            |interface, label, problems| {
                                validate_manifest_object_fields(
                                    interface,
                                    &label,
                                    &["kind", "name", "type", "type_ref", "phase", "cardinality"],
                                    problems,
                                );
                                validate_manifest_required_fields(
                                    interface,
                                    &label,
                                    &["kind"],
                                    problems,
                                );
                                validate_manifest_string_fields(
                                    interface,
                                    &label,
                                    &["kind", "name", "type", "type_ref", "phase", "cardinality"],
                                    problems,
                                );
                            },
                        );
                    }
                },
            );
        },
    );

    validate_manifest_array_objects(
        value,
        "package manifest",
        "capabilities",
        &mut problems,
        |capability, label, problems| {
            validate_manifest_object_fields(
                capability,
                &label,
                &[
                    "id",
                    "description",
                    "schema",
                    "input_schema",
                    "output_schema",
                ],
                problems,
            );
            validate_manifest_required_fields(capability, &label, &["id"], problems);
            validate_manifest_string_fields(capability, &label, &["id", "description"], problems);
        },
    );
    validate_manifest_array_objects(
        value,
        "package manifest",
        "providers",
        &mut problems,
        |provider, label, problems| {
            validate_manifest_object_fields(
                provider,
                &label,
                &[
                    "id",
                    "provider_kind",
                    "capability",
                    "effect_kind",
                    "core_effect_kind",
                    "config",
                    "plane",
                ],
                problems,
            );
            // `"plane": "operator"` marks a capability-FREE provider row
            // (std-telemetry.md T3): configuration for an operator CLI
            // surface, never consulted by the effect admission gate. Such a
            // row declaring a capability would be the decorative admission
            // row M8's honesty audit forbids, so the shapes are mutually
            // exclusive; every non-operator row still requires a capability.
            match provider.get("plane").and_then(Value::as_str) {
                Some("operator") => {
                    validate_manifest_required_fields(
                        provider,
                        &label,
                        &["id", "provider_kind"],
                        problems,
                    );
                    if provider.get("capability").is_some() {
                        problems.push(format!(
                            "{label} declares `plane: operator` and a `capability`; \
                             operator-plane provider rows are capability-free by definition"
                        ));
                    }
                }
                Some(other) => {
                    problems.push(format!(
                        "{label} declares unknown plane `{other}`; the only \
                         recognized value is `operator`"
                    ));
                }
                None => {
                    validate_manifest_required_fields(
                        provider,
                        &label,
                        &["id", "provider_kind", "capability"],
                        problems,
                    );
                }
            }
            validate_manifest_string_fields(
                provider,
                &label,
                &[
                    "id",
                    "provider_kind",
                    "capability",
                    "effect_kind",
                    "core_effect_kind",
                    "plane",
                ],
                problems,
            );
            // Agent-provider rows (`"agent_provider": true` in config;
            // spec/std-agent.md "Open provider registry") may carry a compiled
            // feature report. Its classes must be DR-0015 taxonomy members and
            // its vocabulary the DR-0004/DR-0017 one — an unknown class is a
            // manifest validation error (Static checks item 4).
            if let Some(config) = provider.get("config") {
                if config.get("agent_provider").and_then(Value::as_bool) == Some(true) {
                    validate_agent_provider_feature_report_shape(config, &label, problems);
                }
            }
        },
    );
    validate_manifest_array_objects(
        value,
        "package manifest",
        "profiles",
        &mut problems,
        |profile, label, problems| {
            validate_manifest_object_fields(
                profile,
                &label,
                &[
                    "id",
                    "name",
                    "description",
                    "enforcement_mode",
                    "allowed_capabilities",
                    "config",
                ],
                problems,
            );
            validate_manifest_required_fields(
                profile,
                &label,
                &["id", "name", "allowed_capabilities"],
                problems,
            );
            validate_manifest_string_fields(
                profile,
                &label,
                &["id", "name", "description", "enforcement_mode"],
                problems,
            );
            validate_manifest_string_array_fields(
                profile,
                &label,
                &["allowed_capabilities"],
                problems,
            );
        },
    );
    validate_manifest_array_objects(
        value,
        "package manifest",
        "bindings",
        &mut problems,
        |binding, label, problems| {
            validate_manifest_object_fields(
                binding,
                &label,
                &["id", "program_id", "capability", "provider", "config"],
                problems,
            );
            validate_manifest_required_fields(
                binding,
                &label,
                &["id", "capability", "provider"],
                problems,
            );
            validate_manifest_string_fields(
                binding,
                &label,
                &["id", "capability", "provider"],
                problems,
            );
            validate_manifest_nullable_string_fields(binding, &label, &["program_id"], problems);
        },
    );

    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "package manifest `{}` does not match closed package schema:\n- {}",
            path.display(),
            problems.join("\n- ")
        ))
    }
}

/// Validate an agent-provider row's `config.feature_report` (spec/std-agent.md
/// slices 5/7, Static checks item 4): every entry's `class` must be a DR-0015
/// taxonomy member, `support` and `source` must use the DR-0004/DR-0017
/// vocabulary, and a stated support level carries `native_name` + `dispatch`.
/// Absence of the report is fine (the row contributes only the kind).
fn validate_agent_provider_feature_report_shape(
    config: &Value,
    label: &str,
    problems: &mut Vec<String>,
) {
    let Some(report) = config.get("feature_report") else {
        return;
    };
    let Some(entries) = report.as_array() else {
        problems.push(format!("{label} config.feature_report must be an array"));
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let entry_label = format!("{label} config.feature_report[{index}]");
        let Some(class) = entry.get("class").and_then(Value::as_str) else {
            problems.push(format!("{entry_label} is missing string `class`"));
            continue;
        };
        if !whipplescript_core::AGENT_FEATURE_CLASS_TAXONOMY.contains(&class) {
            problems.push(format!(
                "{entry_label} states unknown feature class `{class}` (not in the DR-0015 taxonomy)"
            ));
        }
        let support = entry.get("support").and_then(Value::as_str);
        match support {
            Some("native" | "emulated" | "request_only" | "unsupported" | "unknown") => {}
            Some(other) => problems.push(format!(
                "{entry_label} states unknown support `{other}`; expected native, emulated, request_only, unsupported, or unknown"
            )),
            None => problems.push(format!("{entry_label} is missing string `support`")),
        }
        match entry.get("source").and_then(Value::as_str) {
            Some("compiled" | "probed") => {}
            Some(other) => problems.push(format!(
                "{entry_label} states unknown source `{other}`; expected compiled or probed"
            )),
            None => problems.push(format!("{entry_label} is missing string `source`")),
        }
        let stated = matches!(support, Some("native" | "emulated" | "request_only"));
        let has_native_name = entry.get("native_name").and_then(Value::as_str).is_some();
        let has_dispatch = entry.get("dispatch").and_then(Value::as_str).is_some();
        if stated && (!has_native_name || !has_dispatch) {
            problems.push(format!(
                "{entry_label} states support without native_name + dispatch"
            ));
        }
    }
}

/// Structural (closed-shape) validation of a construct's DR-0011 `grammar`
/// object: allowed/required keys and JSON types only. Value vocabulary (shape,
/// slot kinds, connectives, binding modes, keyword/target_capability
/// transcription) is enforced when the grammar is parsed
/// (`package_construct_grammar`).
pub fn validate_manifest_construct_grammar_shape(
    grammar: &Value,
    label: &str,
    problems: &mut Vec<String>,
) {
    // The `shape` string discriminates the two manifest-expressible grammar
    // shapes; a `declaration_block` grammar carries `clauses[]` in place of the
    // `effect_operation` `slots`/`payload`/`binding`/`target_capability`.
    if grammar.get("shape").and_then(Value::as_str)
        == Some(CONSTRUCT_GRAMMAR_SHAPE_DECLARATION_BLOCK)
    {
        validate_manifest_declaration_grammar_shape(grammar, label, problems);
        return;
    }
    validate_manifest_object_fields(
        grammar,
        label,
        &[
            "shape",
            "keyword",
            "slots",
            "payload",
            "binding",
            "target_capability",
        ],
        problems,
    );
    validate_manifest_required_fields(
        grammar,
        label,
        &["shape", "keyword", "slots", "binding", "target_capability"],
        problems,
    );
    validate_manifest_string_fields(
        grammar,
        label,
        &["shape", "keyword", "binding", "target_capability"],
        problems,
    );
    validate_manifest_array_objects(
        grammar,
        label,
        "slots",
        problems,
        |slot, label, problems| {
            validate_manifest_object_fields(
                slot,
                &label,
                &["name", "kind", "connective"],
                problems,
            );
            validate_manifest_required_fields(slot, &label, &["name", "kind"], problems);
            validate_manifest_string_fields(
                slot,
                &label,
                &["name", "kind", "connective"],
                problems,
            );
        },
    );
    match grammar.get("payload") {
        None | Some(Value::Null) => {}
        Some(payload) => {
            validate_manifest_object_fields(
                payload,
                &format!("{label}.payload"),
                &["fields"],
                problems,
            );
            validate_manifest_required_fields(
                payload,
                &format!("{label}.payload"),
                &["fields"],
                problems,
            );
            validate_manifest_array_objects(
                payload,
                &format!("{label}.payload"),
                "fields",
                problems,
                |field, label, problems| {
                    validate_manifest_object_fields(
                        field,
                        &label,
                        &["name", "kind", "required"],
                        problems,
                    );
                    validate_manifest_required_fields(field, &label, &["name", "kind"], problems);
                    validate_manifest_string_fields(field, &label, &["name", "kind"], problems);
                    validate_manifest_bool_fields(field, &label, &["required"], problems);
                },
            );
        }
    }
}

/// Closed-shape validation for a `declaration_block` grammar object (the
/// order-free analog of the `effect_operation` branch above): `shape` /
/// `keyword` strings and a `clauses[]` array, each clause an object with
/// `name`/`kind`/`required`/`list`/`unknown_hint`/`missing_summary` and an
/// optional nullable `connective`. Vocabulary and amendment-rule checks
/// (`kind` in the clause vocab, a `flag` carrying no value) live in
/// `package_declaration_grammar`; this only pins the JSON shape.
pub fn validate_manifest_declaration_grammar_shape(
    grammar: &Value,
    label: &str,
    problems: &mut Vec<String>,
) {
    validate_manifest_object_fields(grammar, label, &["shape", "keyword", "clauses"], problems);
    validate_manifest_required_fields(grammar, label, &["shape", "keyword", "clauses"], problems);
    validate_manifest_string_fields(grammar, label, &["shape", "keyword"], problems);
    validate_manifest_array_objects(
        grammar,
        label,
        "clauses",
        problems,
        |clause, label, problems| {
            validate_manifest_object_fields(
                clause,
                &label,
                &[
                    "name",
                    "kind",
                    "required",
                    "list",
                    "connective",
                    "unknown_hint",
                    "missing_summary",
                ],
                problems,
            );
            validate_manifest_required_fields(
                clause,
                &label,
                &[
                    "name",
                    "kind",
                    "required",
                    "list",
                    "unknown_hint",
                    "missing_summary",
                ],
                problems,
            );
            validate_manifest_string_fields(
                clause,
                &label,
                &["name", "kind", "unknown_hint", "missing_summary"],
                problems,
            );
            validate_manifest_nullable_string_fields(clause, &label, &["connective"], problems);
            validate_manifest_bool_fields(clause, &label, &["required", "list"], problems);
        },
    );
}

pub fn validate_manifest_object_fields(
    value: &Value,
    label: &str,
    allowed_fields: &[&str],
    problems: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        problems.push(format!("{label} must be an object"));
        return;
    };
    let allowed = allowed_fields.iter().copied().collect::<BTreeSet<_>>();
    for key in object.keys() {
        if !allowed.contains(key.as_str()) {
            problems.push(format!("{label} field `{key}` is not allowed"));
        }
    }
}

pub fn validate_manifest_required_fields(
    value: &Value,
    label: &str,
    required_fields: &[&str],
    problems: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for field in required_fields {
        if !object.contains_key(*field) {
            problems.push(format!("{label} missing required field `{field}`"));
        }
    }
}

pub fn validate_manifest_string_fields(
    value: &Value,
    label: &str,
    fields: &[&str],
    problems: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for field in fields {
        if object
            .get(*field)
            .is_some_and(|value| value.as_str().is_none_or(|string| string.trim().is_empty()))
        {
            problems.push(format!(
                "{label} field `{field}` must be a non-empty string"
            ));
        }
    }
}

pub fn validate_manifest_nullable_string_fields(
    value: &Value,
    label: &str,
    fields: &[&str],
    problems: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for field in fields {
        if object
            .get(*field)
            .is_some_and(|value| !value.is_null() && value.as_str().is_none())
        {
            problems.push(format!("{label} field `{field}` must be a string or null"));
        }
    }
}

pub fn validate_manifest_bool_fields(
    value: &Value,
    label: &str,
    fields: &[&str],
    problems: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for field in fields {
        if object.get(*field).is_some_and(|value| !value.is_boolean()) {
            problems.push(format!("{label} field `{field}` must be a boolean"));
        }
    }
}

pub fn validate_manifest_string_array_fields(
    value: &Value,
    label: &str,
    fields: &[&str],
    problems: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for field in fields {
        let Some(value) = object.get(*field) else {
            continue;
        };
        let Some(items) = value.as_array() else {
            problems.push(format!("{label} field `{field}` must be an array"));
            continue;
        };
        for (index, item) in items.iter().enumerate() {
            if item.as_str().is_none_or(|string| string.trim().is_empty()) {
                problems.push(format!(
                    "{label}.{field}[{index}] must be a non-empty string"
                ));
            }
        }
    }
}

pub fn validate_manifest_array_objects<F>(
    value: &Value,
    parent_label: &str,
    field: &str,
    problems: &mut Vec<String>,
    mut validate_item: F,
) where
    F: FnMut(&Value, String, &mut Vec<String>),
{
    let Some(items) = value.get(field) else {
        return;
    };
    let Some(items) = items.as_array() else {
        problems.push(format!("{parent_label}.{field} must be an array"));
        return;
    };
    for (index, item) in items.iter().enumerate() {
        let label = format!("{parent_label}.{field}[{index}]");
        if !item.is_object() {
            problems.push(format!("{label} must be an object"));
            continue;
        }
        validate_item(item, label, problems);
    }
}

pub fn validate_package_manifest_identity_uniqueness(
    path: &Path,
    value: &Value,
) -> Result<(), String> {
    let mut problems = Vec::new();
    validate_unique_manifest_collection_ids(value, "libraries", "library", &mut problems);
    validate_unique_manifest_collection_ids(value, "capabilities", "capability", &mut problems);
    validate_unique_manifest_collection_ids(value, "providers", "provider", &mut problems);
    validate_unique_manifest_collection_ids(value, "profiles", "profile", &mut problems);
    validate_unique_manifest_collection_ids(value, "bindings", "binding", &mut problems);

    let mut effect_contract_ids = BTreeMap::<String, String>::new();
    let mut construct_ids = BTreeMap::<String, String>::new();
    for (index, library) in value
        .get("libraries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let library_label =
            optional_json_string(library, "id").unwrap_or_else(|| format!("#{index}"));
        if library.get("effect_contracts").is_some() && library.get("effects").is_some() {
            problems.push(format!(
                "library `{library_label}` declares both `effect_contracts` and `effects`; use `effect_contracts`"
            ));
        }
        for field in ["effect_contracts", "effects"] {
            for contract in library
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(contract_id) = optional_json_string(contract, "id") else {
                    continue;
                };
                let owner = format!("library `{library_label}` {field}");
                validate_unique_manifest_package_id(
                    "effect contract",
                    &contract_id,
                    owner,
                    &mut effect_contract_ids,
                    &mut problems,
                );
                for array_field in [
                    "source_forms",
                    "required_capabilities",
                    "provider_kinds",
                    "projected_facts",
                ] {
                    validate_unique_manifest_string_array(
                        contract,
                        array_field,
                        &format!("effect contract `{contract_id}`"),
                        &mut problems,
                    );
                }
            }
        }
        for construct in library
            .get("constructs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(construct_id) = optional_json_string(construct, "id") else {
                continue;
            };
            validate_unique_manifest_package_id(
                "construct",
                &construct_id,
                format!("library `{library_label}` constructs"),
                &mut construct_ids,
                &mut problems,
            );
        }
    }

    for profile in value
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let profile_label = optional_json_string(profile, "id")
            .or_else(|| optional_json_string(profile, "name"))
            .unwrap_or_else(|| "<unnamed>".to_owned());
        validate_unique_manifest_string_array(
            profile,
            "allowed_capabilities",
            &format!("profile `{profile_label}`"),
            &mut problems,
        );
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "package manifest `{}` has duplicate or ambiguous package identities:\n- {}",
            path.display(),
            problems.join("\n- ")
        ))
    }
}

pub fn validate_unique_manifest_collection_ids(
    value: &Value,
    collection: &str,
    label: &str,
    problems: &mut Vec<String>,
) {
    let mut ids = BTreeSet::new();
    for item in value
        .get(collection)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(id) = optional_json_string(item, "id") else {
            continue;
        };
        if !ids.insert(id.clone()) {
            problems.push(format!("{label} `{id}` is declared more than once"));
        }
    }
}

pub fn validate_unique_manifest_package_id(
    label: &str,
    id: &str,
    owner: String,
    seen: &mut BTreeMap<String, String>,
    problems: &mut Vec<String>,
) {
    if let Some(previous_owner) = seen.insert(id.to_owned(), owner.clone()) {
        problems.push(format!(
            "{label} `{id}` is declared more than once ({previous_owner} and {owner})"
        ));
    }
}

pub fn validate_unique_manifest_string_array(
    value: &Value,
    field: &str,
    owner: &str,
    problems: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for item in value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|item| !item.trim().is_empty())
    {
        if !seen.insert(item) {
            problems.push(format!(
                "{owner} declares `{field}` value `{item}` more than once"
            ));
        }
    }
}

pub fn validate_construct_interface_records(
    path: &Path,
    form: &ConstructRegistration,
    declared_capabilities: &BTreeSet<String>,
    problems: &mut Vec<String>,
) {
    for (direction, interfaces) in [
        ("requires", form.requires.as_slice()),
        ("provides", form.provides.as_slice()),
    ] {
        for interface in interfaces {
            if !PLATFORM_CONSTRUCT_CATALOG.contains_interface_kind(&interface.kind) {
                problems.push(format!(
                    "construct `{}` {direction} interface uses unsupported kind `{}`; expected one of {}",
                    form.id,
                    interface.kind,
                    quoted_platform_values(PLATFORM_CONSTRUCT_CATALOG.interface_kinds.iter().copied())
                ));
            }
            if !PLATFORM_CONSTRUCT_CATALOG.contains_interface_phase(&interface.phase) {
                problems.push(format!(
                    "construct `{}` {direction} interface `{}` uses unsupported phase `{}`; expected one of {}",
                    form.id,
                    interface.kind,
                    interface.phase,
                    quoted_platform_values(PLATFORM_CONSTRUCT_CATALOG.interface_phases.iter().copied())
                ));
            }
            if !PLATFORM_CONSTRUCT_CATALOG.contains_interface_cardinality(&interface.cardinality) {
                problems.push(format!(
                    "construct `{}` {direction} interface `{}` uses unsupported cardinality `{}`; expected one of {}",
                    form.id,
                    interface.kind,
                    interface.cardinality,
                    quoted_platform_values(PLATFORM_CONSTRUCT_CATALOG.interface_cardinalities.iter().copied())
                ));
            }
            if interface.kind == CONSTRUCT_INTERFACE_CAPABILITY {
                match interface.name.as_deref() {
                    Some(capability) => validate_declared_capability(
                        path,
                        declared_capabilities,
                        capability,
                        &format!("construct `{}` {direction} Capability interface", form.id),
                        problems,
                    ),
                    None => problems.push(format!(
                        "construct `{}` {direction} Capability interface must declare `name`",
                        form.id
                    )),
                }
            }
        }
    }
}

pub fn validate_construct_input_schema_fields(
    form: &ConstructRegistration,
    contract: &EffectContract,
    problems: &mut Vec<String>,
) {
    let Some(input_fields) = contract
        .input_schema
        .as_deref()
        .and_then(package_schema_top_level_object_fields)
    else {
        return;
    };
    let construct_fields = form
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field.required))
        .collect::<BTreeMap<_, _>>();

    for input_field in input_fields {
        match construct_fields.get(input_field.as_str()) {
            Some(true) => {}
            Some(false) => problems.push(format!(
                "construct `{}` lowers to `{}` but target input_schema field `{}` is optional in the construct fields",
                form.id, contract.id, input_field
            )),
            None => problems.push(format!(
                "construct `{}` lowers to `{}` but target input_schema field `{}` has no matching required construct field",
                form.id, contract.id, input_field
            )),
        }
    }
}

pub fn package_schema_top_level_object_fields(schema: &str) -> Option<BTreeSet<String>> {
    match serde_json::from_str::<Value>(schema).ok()? {
        Value::Object(fields) => Some(fields.keys().cloned().collect()),
        _ => None,
    }
}

pub fn validate_construct_lowering_interfaces(
    form: &ConstructRegistration,
    lowering: &PlatformConstructLowering,
    problems: &mut Vec<String>,
) {
    for kind in lowering.required_interfaces {
        if !form
            .requires
            .iter()
            .any(|interface| interface.kind == *kind)
        {
            problems.push(format!(
                "construct `{}` uses {} lowering but declares no required `{kind}` interface",
                form.id, lowering.id
            ));
        }
    }
    for kind in lowering.provided_interfaces {
        if !form
            .provides
            .iter()
            .any(|interface| interface.kind == *kind)
        {
            problems.push(format!(
                "construct `{}` uses {} lowering but declares no provided `{kind}` interface",
                form.id, lowering.id
            ));
        }
    }
    if lowering.target_capability == ConstructTargetCapabilityPolicy::RequiredCapabilityCallContract
    {
        let Some(target_capability) = form.target_capability.as_deref() else {
            return;
        };
        if !form.requires.iter().any(|interface| {
            interface.kind == CONSTRUCT_INTERFACE_CAPABILITY
                && interface.name.as_deref() == Some(target_capability)
        }) {
            problems.push(format!(
                "construct `{}` uses {} lowering to `{target_capability}` but declares no required Capability interface named `{target_capability}`",
                form.id, lowering.id
            ));
        }
    }
}

pub fn validate_declared_capability(
    path: &Path,
    declared_capabilities: &BTreeSet<String>,
    capability: &str,
    owner: &str,
    problems: &mut Vec<String>,
) {
    if capability == "*" || declared_capabilities.contains(capability) {
        return;
    }
    problems.push(format!(
        "{owner} in `{}` references undeclared capability `{capability}`",
        path.display()
    ));
}

pub fn package_capability_contracts(
    path: &Path,
    value: &Value,
) -> Result<BTreeMap<String, PackageCapabilityContract>, String> {
    let mut capabilities = BTreeMap::new();
    for capability in value
        .get("capabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let capability_name = required_json_string(capability, "id", "capability")?;
        let schema = capability.get("schema").unwrap_or(&Value::Null);
        let contract = PackageCapabilityContract {
            input_schema: json_schema_fragment(capability.get("input_schema"))
                .or_else(|| json_schema_fragment(schema.get("input"))),
            output_schema: json_schema_fragment(capability.get("output_schema"))
                .or_else(|| json_schema_fragment(schema.get("output"))),
        };
        validate_package_schema_fragment_contract(
            path,
            &format!("capability `{capability_name}`"),
            "input_schema",
            contract.input_schema.as_deref(),
        )?;
        validate_package_schema_fragment_contract(
            path,
            &format!("capability `{capability_name}`"),
            "output_schema",
            contract.output_schema.as_deref(),
        )?;
        if capabilities
            .insert(capability_name.clone(), contract)
            .is_some()
        {
            return Err(format!(
                "package manifest `{}` declares capability `{capability_name}` more than once",
                path.display()
            ));
        }
    }
    Ok(capabilities)
}

pub fn package_provider_contracts(
    path: &Path,
    value: &Value,
) -> Result<Vec<PackageProviderContract>, String> {
    let mut providers = Vec::new();
    for provider in value
        .get("providers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        // Operator-plane rows (`"plane": "operator"`, std-telemetry.md T3)
        // are capability-free by definition and must never become effect
        // providers: skipping them HERE is what keeps them admission-inert —
        // no downstream registry, binding, or `effect_providers` path can
        // ever see one. They surface only through
        // `package_operator_providers`.
        if provider.get("plane").and_then(Value::as_str) == Some("operator") {
            continue;
        }
        providers.push(PackageProviderContract {
            capability: required_json_string(provider, "capability", "provider")
                .map_err(|message| format!("{} in `{}`", message, path.display()))?,
            provider_kind: required_json_string(provider, "provider_kind", "provider")
                .map_err(|message| format!("{} in `{}`", message, path.display()))?,
        });
    }
    Ok(providers)
}

pub fn package_manifest_registry(
    path: &Path,
    value: &Value,
    name: &str,
    version: &str,
    capabilities: &BTreeMap<String, PackageCapabilityContract>,
    providers: &[PackageProviderContract],
) -> Result<ContractRegistry, String> {
    package_manifest_registry_with_privilege(
        path,
        value,
        name,
        version,
        capabilities,
        providers,
        false,
    )
}

/// [`package_manifest_registry`] with the embedded-copy privilege flag: a
/// platform-embedded std manifest may declare an effect contract whose
/// input/output schemas are the parser's contract LABELS (e.g. std.coercion's
/// `schema.coerce.input` / `typed-provider-output`) rather than package schema
/// fragments — the parser is the authority for those contracts, and the
/// registry merge (`upsert_effect_contract`) refuses a manifest copy whose
/// shape drifts from the compiled-in one.
pub fn package_manifest_registry_with_privilege(
    path: &Path,
    value: &Value,
    name: &str,
    version: &str,
    capabilities: &BTreeMap<String, PackageCapabilityContract>,
    providers: &[PackageProviderContract],
    privileged: bool,
) -> Result<ContractRegistry, String> {
    let mut registry = ContractRegistry::default();
    let libraries = value.get("libraries").and_then(Value::as_array);

    if let Some(libraries) = libraries {
        for library in libraries {
            let library_id = optional_json_string(library, "id").unwrap_or_else(|| name.to_owned());
            let library_version =
                optional_json_string(library, "version").unwrap_or_else(|| version.to_owned());
            registry.upsert_library(LibraryRegistration {
                id: library_id.clone(),
                version: library_version.clone(),
                standard: library
                    .get("standard")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            });
            for contract in library
                .get("effect_contracts")
                .or_else(|| library.get("effects"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                registry.upsert_effect_contract(package_effect_contract_with_privilege(
                    path,
                    contract,
                    &library_id,
                    &library_version,
                    capabilities,
                    providers,
                    privileged,
                )?);
            }
            for construct in library
                .get("constructs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                registry.upsert_construct(package_construct(
                    path,
                    construct,
                    &library_id,
                    &library_version,
                )?);
            }
        }
    }

    if registry.libraries.is_empty() {
        registry.upsert_library(LibraryRegistration {
            id: name.to_owned(),
            version: version.to_owned(),
            standard: false,
        });
    }

    if registry.effect_contracts.is_empty() {
        for capability in derived_capability_names(capabilities, providers) {
            let contract_json = json!({"id": capability});
            registry.upsert_effect_contract(package_effect_contract(
                path,
                &contract_json,
                name,
                version,
                capabilities,
                providers,
            )?);
        }
    }

    Ok(registry)
}

pub fn package_construct(
    path: &Path,
    value: &Value,
    library_id: &str,
    version: &str,
) -> Result<ConstructRegistration, String> {
    let id = required_json_string(value, "id", "construct")
        .map_err(|message| format!("{} in `{}`", message, path.display()))?;
    let construct_family = required_json_string(value, "construct_family", "construct")
        .map_err(|message| format!("{} in `{}`", message, path.display()))?;
    let keyword = required_json_string(value, "keyword", "construct")
        .map_err(|message| format!("{} in `{}`", message, path.display()))?;
    let scope = optional_json_string(value, "scope").unwrap_or_else(|| "top_level".to_owned());
    let lowering_target = optional_json_string(value, "lowering_target")
        .unwrap_or_else(|| CONSTRUCT_LOWERING_METADATA_ONLY.to_owned());
    let target_capability = optional_json_string(value, "target_capability");
    let grammar = value
        .get("grammar")
        .map(|grammar| {
            package_construct_grammar(path, grammar, &id, &keyword, target_capability.as_deref())
        })
        .transpose()?;
    // The flat `fields[]` view is derived from the grammar when one is
    // declared (DR-0011: the grammar is the single source of the construct's
    // shape); a construct spelling both is ambiguous and rejected.
    let fields = match &grammar {
        Some(grammar) => {
            if value.get("fields").is_some() {
                return Err(format!(
                    "construct `{id}` declares both `fields` and `grammar` in `{}`; `fields` is derived from `grammar`",
                    path.display()
                ));
            }
            grammar.derive_fields()
        }
        None => value
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|field| package_construct_field(path, field, &id))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let requires = package_construct_interfaces(path, value, "requires", &id)?;
    let provides = package_construct_interfaces(path, value, "provides", &id)?;

    Ok(ConstructRegistration {
        id,
        library_id: library_id.to_owned(),
        version: version.to_owned(),
        construct_family,
        keyword,
        scope,
        grammar,
        fields,
        requires,
        provides,
        lowering_target,
        target_capability,
    })
}

/// Parse and validate a construct's DR-0011 `grammar` object
/// (spec/construct-grammar.md). Both manifest shapes are supported: an
/// `effect_operation` (Shape 2, `<keyword> [<connective> <slot>]* [{ payload }]?
/// as <binding>`) is parsed here; a `declaration_block` (Shape 1, an order-free
/// clause block) is delegated to `package_declaration_grammar`. Slot kinds,
/// connectives, and binding modes are validated against the core vocabulary,
/// and `grammar.keyword` / `grammar.target_capability` must transcribe the
/// construct's own values.
pub fn package_construct_grammar(
    path: &Path,
    value: &Value,
    form_id: &str,
    construct_keyword: &str,
    construct_target_capability: Option<&str>,
) -> Result<ConstructGrammar, String> {
    let owner = format!("construct `{form_id}` grammar");
    let in_path = format!("in `{}`", path.display());
    let shape = required_json_string(value, "shape", &owner)
        .map_err(|message| format!("{message} {in_path}"))?;
    if shape == CONSTRUCT_GRAMMAR_SHAPE_DECLARATION_BLOCK {
        return package_declaration_grammar(value, &owner, &in_path, shape, construct_keyword);
    }
    if shape != CONSTRUCT_GRAMMAR_SHAPE_EFFECT_OPERATION {
        return Err(format!(
            "{owner} uses unsupported shape `{shape}`; expected `{CONSTRUCT_GRAMMAR_SHAPE_EFFECT_OPERATION}` {in_path}"
        ));
    }
    let keyword = required_json_string(value, "keyword", &owner)
        .map_err(|message| format!("{message} {in_path}"))?;
    if keyword != construct_keyword {
        return Err(format!(
            "{owner} keyword `{keyword}` does not match the construct keyword `{construct_keyword}` {in_path}"
        ));
    }
    let mut slots = Vec::new();
    for (index, slot) in value
        .get("slots")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{owner} must have a `slots` array {in_path}"))?
        .iter()
        .enumerate()
    {
        let slot_owner = format!("{owner} slots[{index}]");
        let name = required_json_string(slot, "name", &slot_owner)
            .map_err(|message| format!("{message} {in_path}"))?;
        let kind = required_json_string(slot, "kind", &slot_owner)
            .map_err(|message| format!("{message} {in_path}"))?;
        if !CONSTRUCT_GRAMMAR_SLOT_KINDS.contains(&kind.as_str()) {
            return Err(format!(
                "{slot_owner} uses unsupported kind `{kind}`; expected one of {} {in_path}",
                quoted_platform_values(CONSTRUCT_GRAMMAR_SLOT_KINDS.iter().copied())
            ));
        }
        let connective = optional_json_string(slot, "connective");
        if let Some(connective) = connective.as_deref() {
            if !CONSTRUCT_GRAMMAR_CONNECTIVES.contains(&connective) {
                return Err(format!(
                    "{slot_owner} uses unsupported connective `{connective}`; expected one of {} {in_path}",
                    quoted_platform_values(CONSTRUCT_GRAMMAR_CONNECTIVES.iter().copied())
                ));
            }
        }
        slots.push(ConstructGrammarSlot {
            name,
            kind,
            connective,
        });
    }
    let payload = match value.get("payload") {
        None | Some(Value::Null) => None,
        Some(payload) => {
            let mut fields = Vec::new();
            for (index, field) in payload
                .get("fields")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{owner} payload must have a `fields` array {in_path}"))?
                .iter()
                .enumerate()
            {
                let field_owner = format!("{owner} payload.fields[{index}]");
                let name = required_json_string(field, "name", &field_owner)
                    .map_err(|message| format!("{message} {in_path}"))?;
                let kind = required_json_string(field, "kind", &field_owner)
                    .map_err(|message| format!("{message} {in_path}"))?;
                if kind != "expression" {
                    return Err(format!(
                        "{field_owner} uses unsupported kind `{kind}`; payload fields are `expression` {in_path}"
                    ));
                }
                fields.push(ConstructGrammarPayloadField {
                    name,
                    kind,
                    required: field
                        .get("required")
                        .and_then(Value::as_bool)
                        .unwrap_or(true),
                });
            }
            Some(fields)
        }
    };
    let binding = required_json_string(value, "binding", &owner)
        .map_err(|message| format!("{message} {in_path}"))?;
    if !CONSTRUCT_GRAMMAR_BINDING_MODES.contains(&binding.as_str()) {
        return Err(format!(
            "{owner} uses unsupported binding `{binding}`; expected one of {} {in_path}",
            quoted_platform_values(CONSTRUCT_GRAMMAR_BINDING_MODES.iter().copied())
        ));
    }
    let target_capability = required_json_string(value, "target_capability", &owner)
        .map_err(|message| format!("{message} {in_path}"))?;
    if construct_target_capability != Some(target_capability.as_str()) {
        return Err(format!(
            "{owner} target_capability `{target_capability}` does not match the construct target_capability `{}` {in_path}",
            construct_target_capability.unwrap_or("<none>")
        ));
    }
    Ok(ConstructGrammar {
        shape,
        keyword,
        slots,
        payload,
        binding,
        target_capability,
        clauses: None,
    })
}

/// Parse and validate a construct's DR-0011 `declaration_block` grammar object
/// (Shape 1, spec/construct-grammar.md). The order-free analog of the
/// `effect_operation` body in `package_construct_grammar`: `grammar.keyword`
/// must transcribe the construct keyword, and each `clauses[]` entry carries a
/// `name` (may be multi-word), a `kind` from `CONSTRUCT_GRAMMAR_CLAUSE_KINDS`,
/// `required`/`list` flags, an optional `connective` from
/// `CONSTRUCT_GRAMMAR_CLAUSE_CONNECTIVES`, plus `unknown_hint`/`missing_summary`
/// diagnostics. Enforces the 2026-07-08 amendment rules (a `flag` carries no
/// value: `list == false` and no connective; `list` is only for a value kind) —
/// the same rules `build.rs` applies to the compiled-in decl table. The
/// resulting `ConstructGrammar` carries `slots`/`payload`/`binding` empty and
/// `clauses: Some(..)`, so `derive_fields` takes the declaration_block path.
pub fn package_declaration_grammar(
    value: &Value,
    owner: &str,
    in_path: &str,
    shape: String,
    construct_keyword: &str,
) -> Result<ConstructGrammar, String> {
    let keyword = required_json_string(value, "keyword", owner)
        .map_err(|message| format!("{message} {in_path}"))?;
    if keyword != construct_keyword {
        return Err(format!(
            "{owner} keyword `{keyword}` does not match the construct keyword `{construct_keyword}` {in_path}"
        ));
    }
    let mut clauses = Vec::new();
    for (index, clause) in value
        .get("clauses")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{owner} must have a `clauses` array {in_path}"))?
        .iter()
        .enumerate()
    {
        let clause_owner = format!("{owner} clauses[{index}]");
        let name = required_json_string(clause, "name", &clause_owner)
            .map_err(|message| format!("{message} {in_path}"))?;
        let kind = required_json_string(clause, "kind", &clause_owner)
            .map_err(|message| format!("{message} {in_path}"))?;
        if !CONSTRUCT_GRAMMAR_CLAUSE_KINDS.contains(&kind.as_str()) {
            return Err(format!(
                "{clause_owner} uses unsupported kind `{kind}`; expected one of {} {in_path}",
                quoted_platform_values(CONSTRUCT_GRAMMAR_CLAUSE_KINDS.iter().copied())
            ));
        }
        let connective = optional_json_string(clause, "connective");
        if let Some(connective) = connective.as_deref() {
            if !CONSTRUCT_GRAMMAR_CLAUSE_CONNECTIVES.contains(&connective) {
                return Err(format!(
                    "{clause_owner} uses unsupported connective `{connective}`; expected one of {} {in_path}",
                    quoted_platform_values(CONSTRUCT_GRAMMAR_CLAUSE_CONNECTIVES.iter().copied())
                ));
            }
        }
        let required = clause
            .get("required")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("{clause_owner} must have a bool `required` {in_path}"))?;
        let list = clause
            .get("list")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("{clause_owner} must have a bool `list` {in_path}"))?;
        // Amendment rule: a `flag` carries no value, so it can be neither a
        // list nor connective-introduced; `list` is only meaningful for a value
        // kind. Mirrors `build.rs`'s `emit_declaration_row`.
        if kind == "flag" {
            if list {
                return Err(format!(
                    "{clause_owner} is a `flag` and cannot set `list: true` (a flag carries no value) {in_path}"
                ));
            }
            if connective.is_some() {
                return Err(format!(
                    "{clause_owner} is a `flag` and cannot carry a connective (a flag carries no value) {in_path}"
                ));
            }
        }
        // `unknown_hint`/`missing_summary` are validation diagnostics, required
        // on every clause (closed-shape check pins their presence; parsed here
        // to keep the fail-fast contract) but not carried on the grammar node.
        required_json_string(clause, "unknown_hint", &clause_owner)
            .map_err(|message| format!("{message} {in_path}"))?;
        required_json_string(clause, "missing_summary", &clause_owner)
            .map_err(|message| format!("{message} {in_path}"))?;
        clauses.push(ConstructGrammarClause {
            name,
            kind,
            required,
            list,
            connective,
        });
    }
    Ok(ConstructGrammar {
        shape,
        keyword,
        slots: Vec::new(),
        payload: None,
        binding: "none".to_owned(),
        target_capability: String::new(),
        clauses: Some(clauses),
    })
}

pub fn package_construct_field(
    path: &Path,
    value: &Value,
    form_id: &str,
) -> Result<ConstructField, String> {
    let owner = format!("construct `{form_id}` field");
    let name = required_json_string(value, "name", &owner)
        .map_err(|message| format!("{} in `{}`", message, path.display()))?;
    let kind = required_json_string(value, "kind", &owner)
        .map_err(|message| format!("{} in `{}`", message, path.display()))?;
    Ok(ConstructField {
        name,
        kind,
        required: value
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    })
}

pub fn package_construct_interfaces(
    path: &Path,
    value: &Value,
    direction: &str,
    construct_id: &str,
) -> Result<Vec<ConstructInterface>, String> {
    value
        .get(direction)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|interface| package_construct_interface(path, interface, direction, construct_id))
        .collect()
}

pub fn package_construct_interface(
    path: &Path,
    value: &Value,
    direction: &str,
    construct_id: &str,
) -> Result<ConstructInterface, String> {
    let owner = format!("construct `{construct_id}` {direction} interface");
    let kind = required_json_string(value, "kind", &owner)
        .map_err(|message| format!("{} in `{}`", message, path.display()))?;
    let name = optional_json_string(value, "name");
    let type_ref =
        optional_json_string(value, "type").or_else(|| optional_json_string(value, "type_ref"));
    let phase = optional_json_string(value, "phase")
        .unwrap_or_else(|| CONSTRUCT_INTERFACE_PHASE_COMPILE_RUNTIME.to_owned());
    let cardinality = optional_json_string(value, "cardinality")
        .unwrap_or_else(|| CONSTRUCT_INTERFACE_CARDINALITY_EXACTLY_ONE.to_owned());

    Ok(ConstructInterface {
        kind,
        name,
        type_ref,
        phase,
        cardinality,
    })
}

pub fn derived_capability_names(
    capabilities: &BTreeMap<String, PackageCapabilityContract>,
    providers: &[PackageProviderContract],
) -> BTreeSet<String> {
    let mut names = capabilities.keys().cloned().collect::<BTreeSet<_>>();
    for provider in providers {
        names.insert(provider.capability.clone());
    }
    names
}

pub fn package_effect_contract(
    path: &Path,
    value: &Value,
    library_id: &str,
    version: &str,
    capabilities: &BTreeMap<String, PackageCapabilityContract>,
    providers: &[PackageProviderContract],
) -> Result<EffectContract, String> {
    package_effect_contract_with_privilege(
        path,
        value,
        library_id,
        version,
        capabilities,
        providers,
        false,
    )
}

/// [`package_effect_contract`] with the embedded-copy privilege flag: only a
/// platform-embedded std manifest may carry the parser's contract schema
/// LABELS (`schema.coerce.input`, `typed-provider-output`, …) in place of
/// package schema fragments — third-party fragments stay strictly validated.
pub fn package_effect_contract_with_privilege(
    path: &Path,
    value: &Value,
    library_id: &str,
    version: &str,
    capabilities: &BTreeMap<String, PackageCapabilityContract>,
    providers: &[PackageProviderContract],
    privileged: bool,
) -> Result<EffectContract, String> {
    let id = required_json_string(value, "id", "effect contract")
        .map_err(|message| format!("{} in `{}`", message, path.display()))?;
    let capability_contract = capabilities.get(&id);
    let output_schema = json_schema_fragment(value.get("output_schema"))
        .or_else(|| capability_contract.and_then(|contract| contract.output_schema.clone()));
    let input_schema = json_schema_fragment(value.get("input_schema"))
        .or_else(|| capability_contract.and_then(|contract| contract.input_schema.clone()));
    if !privileged {
        validate_package_schema_fragment_contract(
            path,
            &format!("effect contract `{id}`"),
            "input_schema",
            input_schema.as_deref(),
        )?;
        validate_package_schema_fragment_contract(
            path,
            &format!("effect contract `{id}`"),
            "output_schema",
            output_schema.as_deref(),
        )?;
    }
    let source_forms = optional_json_string_array(value, "source_forms")
        .filter(|forms| !forms.is_empty())
        .unwrap_or_else(|| vec![format!("call {id}")]);
    let required_capabilities = optional_json_string_array(value, "required_capabilities")
        .filter(|capabilities| !capabilities.is_empty())
        .unwrap_or_else(|| vec![id.clone()]);
    let provider_kinds = optional_json_string_array(value, "provider_kinds")
        .filter(|kinds| !kinds.is_empty())
        .unwrap_or_else(|| {
            providers
                .iter()
                .filter(|provider| provider.capability == id)
                .map(|provider| provider.provider_kind.clone())
                .collect()
        });
    let projected_facts =
        optional_json_string_array(value, "projected_facts").unwrap_or_else(|| {
            if output_schema.is_some() {
                vec!["effect.output".to_owned()]
            } else {
                Vec::new()
            }
        });
    let validation = package_validation_mode(value, output_schema.is_some())?;

    Ok(EffectContract {
        id,
        library_id: library_id.to_owned(),
        version: version.to_owned(),
        effect_kind: optional_json_string_any(value, &["effect_kind", "core_effect_kind"])
            .unwrap_or_else(|| "capability.call".to_owned()),
        source_forms,
        input_schema,
        output_schema,
        required_capabilities,
        provider_kinds,
        projected_facts,
        validation,
    })
}

pub fn package_validation_mode(
    value: &Value,
    has_output_schema: bool,
) -> Result<TypedOutputValidation, String> {
    match value.get("validation").and_then(Value::as_str) {
        Some("none") => Ok(TypedOutputValidation::None),
        Some("runtime_boundary") | Some("runtime") => Ok(TypedOutputValidation::RuntimeBoundary),
        Some(other) => Err(format!(
            "effect contract validation must be `none` or `runtime_boundary`, got `{other}`"
        )),
        None if has_output_schema => Ok(TypedOutputValidation::RuntimeBoundary),
        None => Ok(TypedOutputValidation::None),
    }
}

pub fn validate_package_schema_fragment_contract(
    path: &Path,
    owner: &str,
    field: &str,
    schema: Option<&str>,
) -> Result<(), String> {
    let Some(schema) = schema else {
        return Ok(());
    };
    let mut errors = Vec::new();
    validate_package_schema_fragment_shape(schema, field, &mut errors, 0);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{owner} in `{}` has invalid {field}: {}",
            path.display(),
            errors.join("; ")
        ))
    }
}

pub fn validate_package_schema_fragment_shape(
    schema: &str,
    label: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    if depth > 32 {
        errors.push(format!("{label} exceeded package schema recursion limit"));
        return;
    }
    match serde_json::from_str::<Value>(schema) {
        Ok(fragment) => validate_package_schema_shape_value(&fragment, label, errors, depth + 1),
        Err(_) => validate_package_schema_type_name(schema, label, errors),
    }
}

pub fn validate_package_schema_shape_value(
    schema: &Value,
    label: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    if depth > 32 {
        errors.push(format!("{label} exceeded package schema recursion limit"));
        return;
    }
    match schema {
        Value::String(name) => validate_package_schema_type_name(name, label, errors),
        Value::Object(fields) => {
            for (field, field_schema) in fields {
                if field.trim().is_empty() {
                    errors.push(format!("{label} contains an empty field name"));
                    continue;
                }
                validate_package_schema_shape_value(
                    field_schema,
                    &format!("{label}.{field}"),
                    errors,
                    depth + 1,
                );
            }
        }
        Value::Array(items) if items.len() == 1 => {
            validate_package_schema_shape_value(&items[0], &format!("{label}[]"), errors, depth + 1)
        }
        Value::Array(_) => errors.push(format!("{label} uses unsupported package tuple schema")),
        Value::Bool(_) | Value::Number(_) | Value::Null => errors.push(format!(
            "{label} uses unsupported package schema fragment `{schema}`"
        )),
    }
}

pub fn validate_package_schema_type_name(name: &str, label: &str, errors: &mut Vec<String>) {
    if !matches!(
        name,
        "json"
            | "any"
            | "string"
            | "int"
            | "integer"
            | "float"
            | "number"
            | "bool"
            | "boolean"
            | "null"
    ) {
        errors.push(format!("{label} uses unsupported package type `{name}`"));
    }
}

pub fn json_schema_fragment(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(schema)) if !schema.trim().is_empty() => Some(schema.clone()),
        Some(Value::Null) | None => None,
        Some(schema) => Some(schema.to_string()),
    }
}
