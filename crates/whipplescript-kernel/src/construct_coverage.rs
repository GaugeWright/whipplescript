//! Checked construct edges for bounded RC-3 admission slices.
//!
//! The caller supplies the registry and local package-source mapping from the
//! same immutable package snapshot used to check the IR. This pure extractor
//! cannot prove that provenance itself, cover other construct-bearing IR
//! forms, or close a Home operation roster.

use std::collections::BTreeSet;
use std::path::PathBuf;

use whipplescript_core::{ConstructRegistration, ContractRegistry};
use whipplescript_parser::{
    IrConstructUse, IrDeclarationConstruct, IrEffectKind, IrPackageCall, IrProgram,
};
use whipplescript_store::program_imports::{
    ProgramConstructCapture, ProgramConstructEdge, ProgramConstructMeaning, ProgramConstructScope,
    ProgramConstructUse, ProgramDeclarationCapture, ProgramDeclarationEdge, ProgramDeclarationUse,
    ProgramImportWitness, ProgramPackageCallCapture, ProgramPackageCallScope,
    ProgramPackageCallUse,
};

use crate::exec_http::sha256_hex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedConstructSource<'a> {
    pub library_id: &'a str,
    pub package_name: &'a str,
    pub source_digest: &'a str,
}

pub struct CheckedConstructBasis<'a> {
    pub registry: &'a ContractRegistry,
    pub sources: &'a [ResolvedConstructSource<'a>],
}

fn matches(form: &ConstructRegistration, use_form: &IrConstructUse) -> bool {
    form.keyword == use_form.keyword
        && form.scope == use_form.scope
        && form.construct_family == use_form.construct_family
        && form.lowering_target == use_form.lowering_target
        && form.target_capability.as_deref() == Some(use_form.target_capability.as_str())
}

fn matches_declaration(form: &ConstructRegistration, declaration: &IrDeclarationConstruct) -> bool {
    form.keyword == declaration.keyword
        && form.scope == declaration.scope
        && form.construct_family == declaration.family
        && form.lowering_target == declaration.lowering
        && form.target_capability.is_none()
}

/// Select an embedded manifest only when its registration matches a
/// compiler-inventoried declaration. A library inferred from effect metadata
/// alone is not evidence that its declaration syntax appeared in this source.
pub fn registry_matches_declaration_inventory(
    program: &IrProgram,
    registry: &ContractRegistry,
) -> bool {
    program
        .declaration_constructs
        .as_ref()
        .is_some_and(|declarations| {
            declarations.iter().any(|declaration| {
                registry
                    .constructs
                    .iter()
                    .any(|form| matches_declaration(form, declaration))
            })
        })
}

/// Resolve the vocabulary shipped by one host from its exact embedded
/// manifest bytes. A declaration can select its standard provider without an
/// explicit import; rule-effect constructs still need the owning `use` at
/// capture. The caller binds `embedded` to the compiler artifact identity in
/// the import basis it admits with this registry.
pub fn embedded_std_registry_for_program(
    program: &IrProgram,
    embedded: &[(&str, &str)],
) -> Result<ContractRegistry, String> {
    let mut registry = program.contract_registry();
    for (name, json) in embedded {
        let path = PathBuf::from(format!("<embedded:{name}>"));
        let manifest = crate::package_registry::package_manifest_from_json_with_embedded(
            &path,
            (*json).to_owned(),
            embedded,
        )?;
        if program.uses.iter().any(|use_decl| use_decl.name == *name)
            || registry_matches_declaration_inventory(program, &manifest.registry)
        {
            registry.merge(manifest.registry);
        }
    }
    Ok(registry)
}

/// The provider-free shipped standard set, for kernel fixtures that admit
/// through a product facade. The kernel cannot name a product's set; this
/// mirrors the hosted one, which `whipplescript-host-do` guards for drift.
#[cfg(test)]
pub(crate) const TEST_SHIPPED_STD_MANIFESTS: &[(&str, &str)] = &[
    (
        "std.agent",
        include_str!("../../../std/manifests/agent.json"),
    ),
    (
        "std.coercion",
        include_str!("../../../std/manifests/coercion.json"),
    ),
    (
        "std.coord",
        include_str!("../../../std/manifests/coord.json"),
    ),
    (
        "std.files",
        include_str!("../../../std/manifests/files.json"),
    ),
    (
        "std.image",
        include_str!("../../../std/manifests/image.json"),
    ),
    (
        "std.ingress",
        include_str!("../../../std/manifests/ingress.json"),
    ),
    (
        "std.custody",
        include_str!("../../../std/manifests/custody.json"),
    ),
    (
        "std.memory",
        include_str!("../../../std/manifests/memory.json"),
    ),
    ("std.vcs", include_str!("../../../std/manifests/vcs.json")),
    (
        "std.messaging",
        include_str!("../../../std/manifests/messaging.json"),
    ),
    (
        "std.script",
        include_str!("../../../std/manifests/script.json"),
    ),
    (
        "std.telemetry",
        include_str!("../../../std/manifests/telemetry.json"),
    ),
    ("std.time", include_str!("../../../std/manifests/time.json")),
    (
        "std.tracker",
        include_str!("../../../std/manifests/tracker.json"),
    ),
];

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Inventory the capability-call field family without interpreting its opaque
/// argument as a reference or inferring a live dependency from a capability
/// name. The exhaustive effect-kind match is intentional: adding a new effect
/// must make its package-call classification an accepting-boundary choice.
pub fn capture_package_calls(program: &IrProgram) -> Result<ProgramPackageCallCapture, String> {
    let mut examined = Vec::new();
    for (rule, effect) in program.rules.iter().flat_map(|rule| {
        rule.metadata
            .effects
            .iter()
            .map(move |effect| (rule, effect))
    }) {
        let is_call = match &effect.kind {
            IrEffectKind::CapabilityCall => true,
            IrEffectKind::AgentTell
            | IrEffectKind::SchemaCoerce
            | IrEffectKind::EventEmit
            | IrEffectKind::WorkflowInvoke
            | IrEffectKind::TimerWait
            | IrEffectKind::ExecCommand
            | IrEffectKind::HttpRequest
            | IrEffectKind::MintCredential
            | IrEffectKind::RotateCredential
            | IrEffectKind::RevokeCredential
            | IrEffectKind::TrackerFile
            | IrEffectKind::TrackerClaim
            | IrEffectKind::TrackerRenew
            | IrEffectKind::TrackerRelease
            | IrEffectKind::TrackerFinish
            | IrEffectKind::TrackerMembership
            | IrEffectKind::TrackerInspect
            | IrEffectKind::LeaseAcquire
            | IrEffectKind::LeaseRenew
            | IrEffectKind::LedgerAppend
            | IrEffectKind::CounterConsume
            | IrEffectKind::SignalEmit
            | IrEffectKind::FileRead
            | IrEffectKind::FileWrite
            | IrEffectKind::FileImport
            | IrEffectKind::FileExport => false,
        };
        if is_call != effect.package_call.is_some() {
            return Err(format!(
                "effect `{}` has an unclassified package-call field",
                effect.id
            ));
        }
        if let Some(call) = &effect.package_call {
            // No `..`: a new reference-capable field cannot be silently
            // omitted from this accepting witness.
            let IrPackageCall {
                target,
                argument,
                tracker_resources,
            } = call;
            examined.push(ProgramPackageCallUse {
                occurrence: examined.len(),
                rule_name: rule.name.clone(),
                effect_id: effect.id.clone(),
                target: target.clone(),
                argument: argument.clone(),
                tracker_resources: tracker_resources.clone(),
            });
        }
    }
    let json = serde_json::to_vec(&examined).map_err(|error| error.to_string())?;
    Ok(ProgramPackageCallCapture {
        scope: ProgramPackageCallScope::CapabilityCallV1,
        examined,
        digest: sha256_hex(&json),
    })
}

pub fn capture(
    program: &IrProgram,
    registry: &ContractRegistry,
    imports: &ProgramImportWitness,
    sources: &[ResolvedConstructSource<'_>],
) -> Result<ProgramConstructCapture, String> {
    let imported = program
        .uses
        .iter()
        .map(|use_decl| use_decl.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut examined = Vec::new();
    let mut edges = Vec::new();
    for (occurrence, use_form) in program.construct_uses().into_iter().enumerate() {
        let mut matches = registry
            .constructs
            .iter()
            .filter(|form| matches(form, use_form));
        let form = matches
            .next()
            .ok_or_else(|| format!("unresolved checked construct `{}`", use_form.keyword))?;
        if matches.next().is_some() {
            return Err(format!(
                "checked construct `{}` resolves to more than one registration",
                use_form.keyword
            ));
        }
        if !registry.effect_contracts.iter().any(|contract| {
            contract.id == use_form.target_capability && contract.effect_kind == "capability.call"
        }) {
            return Err(format!(
                "checked construct `{}` lacks its capability.call effect contract",
                use_form.keyword
            ));
        }
        let (provider_package, provider_source_digest) = if form.library_id.starts_with("std.") {
            if !imported.contains(form.library_id.as_str()) {
                return Err(format!(
                    "checked construct `{}` has no owning std import",
                    use_form.keyword
                ));
            }
            (
                form.library_id.as_str(),
                imports.compiler_artifact_digest.as_str(),
            )
        } else {
            let mut owners = sources
                .iter()
                .filter(|source| source.library_id == form.library_id);
            let owner = owners.next().ok_or_else(|| {
                format!(
                    "checked construct `{}` has no attested package source",
                    use_form.keyword
                )
            })?;
            if owners.next().is_some()
                || !imported.contains(owner.package_name)
                || !imports.edges.iter().any(|edge| {
                    edge.import == owner.package_name && edge.source_digest == owner.source_digest
                })
            {
                return Err(format!(
                    "checked construct `{}` has an ambiguous or unbound package source",
                    use_form.keyword
                ));
            }
            (owner.package_name, owner.source_digest)
        };
        if !is_digest(provider_source_digest) {
            return Err(format!(
                "checked construct `{}` lacks an exact provider source digest",
                use_form.keyword
            ));
        }
        let observed = ProgramConstructUse {
            occurrence,
            keyword: use_form.keyword.clone(),
            scope: use_form.scope.clone(),
            family: use_form.construct_family.clone(),
            lowering: use_form.lowering_target.clone(),
            capability: use_form.target_capability.clone(),
        };
        edges.push(ProgramConstructEdge {
            use_form: observed.clone(),
            registration_id: form.id.clone(),
            library_id: form.library_id.clone(),
            registration_version: form.version.clone(),
            provider_package: provider_package.to_owned(),
            provider_source_digest: provider_source_digest.to_owned(),
            meaning: ProgramConstructMeaning::LiveDependency,
        });
        examined.push(observed);
    }
    let edge_json = serde_json::to_vec(&edges).map_err(|error| error.to_string())?;
    Ok(ProgramConstructCapture {
        scope: ProgramConstructScope::RuleEffect,
        examined,
        edges,
        edge_digest: sha256_hex(&edge_json),
    })
}

/// Resolve the compiler's seven standard declaration forms against their
/// checked registry. The inventory is compiler-owned, but this function does
/// not prove the caller compiled it from the source named by `imports`; the
/// accepting boundary must retain that same source and registry snapshot.
/// Package-authored declaration forms remain outside this bounded slice.
pub fn capture_declarations(
    program: &IrProgram,
    registry: &ContractRegistry,
    imports: &ProgramImportWitness,
) -> Result<ProgramDeclarationCapture, String> {
    let declarations = program
        .declaration_constructs
        .as_ref()
        .ok_or_else(|| "checked program has no declaration inventory".to_owned())?;
    if !is_digest(&imports.compiler_artifact_digest) {
        return Err("declaration capture lacks an exact compiler artifact digest".into());
    }
    let compiler_owned = program
        .contract_registry()
        .libraries
        .into_iter()
        .map(|library| library.id)
        .collect::<BTreeSet<_>>();
    let mut examined = Vec::with_capacity(declarations.len());
    let mut edges = Vec::with_capacity(declarations.len());
    let mut previous = None;
    for declaration in declarations {
        if previous.is_some_and(|index| declaration.occurrence <= index) {
            return Err("checked declaration inventory is not in effective-source order".into());
        }
        previous = Some(declaration.occurrence);
        let mut matches = registry
            .constructs
            .iter()
            .filter(|form| matches_declaration(form, declaration));
        let form = matches.next().ok_or_else(|| {
            format!(
                "unresolved checked declaration `{}` lowering to `{}`",
                declaration.keyword, declaration.lowering
            )
        })?;
        if matches.next().is_some() {
            return Err(format!(
                "checked declaration `{}` resolves to more than one registration",
                declaration.keyword
            ));
        }
        if !form.library_id.starts_with("std.")
            || !compiler_owned.contains(&form.library_id)
            || !registry
                .libraries
                .iter()
                .any(|library| library.id == form.library_id && library.standard)
        {
            return Err(format!(
                "checked declaration `{}` lacks its compiler-owned std library",
                declaration.keyword
            ));
        }
        let observed = ProgramDeclarationUse {
            occurrence: declaration.occurrence,
            keyword: declaration.keyword.clone(),
            name: declaration.name.clone(),
            scope: declaration.scope.clone(),
            family: declaration.family.clone(),
            lowering: declaration.lowering.clone(),
        };
        edges.push(ProgramDeclarationEdge {
            declaration: observed.clone(),
            registration_id: form.id.clone(),
            library_id: form.library_id.clone(),
            registration_version: form.version.clone(),
            provider_package: form.library_id.clone(),
            provider_source_digest: imports.compiler_artifact_digest.clone(),
            meaning: ProgramConstructMeaning::LiveDependency,
        });
        examined.push(observed);
    }
    let edge_json = serde_json::to_vec(&edges).map_err(|error| error.to_string())?;
    Ok(ProgramDeclarationCapture {
        examined,
        edges,
        edge_digest: sha256_hex(&edge_json),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_core::{
        std_messaging_send_construct, std_messaging_send_effect_contract, LibraryRegistration,
    };
    use whipplescript_parser::{IrUse, IrUseKind};

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn program() -> IrProgram {
        let source = r##"use std.messaging
workflow Notify
class Trigger { id string }
channel alerts { provider fixture destination "#ops" }
rule notify
  when Trigger as t
=> {
  send via alerts { text "hello" } as sent
}
"##;
        let compiled = whipplescript_parser::compile_program(source);
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        compiled.ir.unwrap()
    }

    #[test]
    fn package_call_inventory_covers_ordinary_calls_and_refuses_missing_metadata() {
        let compiled = whipplescript_parser::compile_program(include_str!(
            "../../../examples/package-memory.whip"
        ));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let mut checked_program = compiled.ir.unwrap();
        let captured =
            capture_package_calls(&checked_program).expect("all capability calls inventoried");
        assert_eq!(captured.scope, ProgramPackageCallScope::CapabilityCallV1);
        assert_eq!(captured.examined.len(), 2);
        assert_eq!(captured.examined[0].target, "memory.query");
        assert_eq!(captured.examined[0].argument.as_deref(), Some("issue"));
        assert_eq!(captured.examined[1].target, "memory.write");
        assert_eq!(captured.examined[1].argument.as_deref(), Some("turn"));

        let mut non_call = checked_program.clone();

        let first_call = checked_program
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind == IrEffectKind::CapabilityCall)
            .unwrap();
        first_call.package_call = None;
        assert!(capture_package_calls(&checked_program)
            .unwrap_err()
            .contains("unclassified package-call field"));

        let effect = non_call
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .find(|effect| effect.kind != IrEffectKind::CapabilityCall)
            .unwrap();
        effect.package_call = Some(IrPackageCall {
            target: "invented.reference".into(),
            argument: Some("opaque".into()),
            tracker_resources: vec![],
        });
        assert!(capture_package_calls(&non_call)
            .unwrap_err()
            .contains("unclassified package-call field"));
    }

    fn registry() -> ContractRegistry {
        ContractRegistry {
            constructs: vec![std_messaging_send_construct()],
            effect_contracts: vec![std_messaging_send_effect_contract()],
            ..ContractRegistry::default()
        }
    }

    fn standard_declaration(
        id: &str,
        library: &str,
        keyword: &str,
        family: &str,
        lowering: &str,
    ) -> ConstructRegistration {
        ConstructRegistration {
            id: id.into(),
            library_id: library.into(),
            version: "0.1.0".into(),
            construct_family: family.into(),
            keyword: keyword.into(),
            scope: "top_level".into(),
            grammar: None,
            fields: Vec::new(),
            requires: Vec::new(),
            provides: Vec::new(),
            lowering_target: lowering.into(),
            target_capability: None,
        }
    }

    #[test]
    fn declaration_capture_resolves_both_source_variants_and_refuses_unknown_or_ambiguous() {
        let signal = standard_declaration(
            "ingress.signal",
            "std.ingress",
            "signal",
            "declaration_block",
            "metadata_only",
        );
        let clock = standard_declaration(
            "time.clock_source",
            "std.time",
            "source clock",
            "source_declaration",
            "clock_source",
        );
        let generic = standard_declaration(
            "ingress.source",
            "std.ingress",
            "source",
            "source_declaration",
            "signal_source",
        );
        let registry = ContractRegistry {
            libraries: vec![
                LibraryRegistration {
                    id: "std.ingress".into(),
                    version: "0.1.0".into(),
                    standard: true,
                },
                LibraryRegistration {
                    id: "std.time".into(),
                    version: "0.1.0".into(),
                    standard: true,
                },
            ],
            constructs: vec![signal, clock.clone(), generic],
            ..ContractRegistry::default()
        };
        for (source, expected) in [
            (
                include_str!("../../../examples/clock-source.whip"),
                "time.clock_source",
            ),
            (
                include_str!("../../../examples/ingress-file-source.whip"),
                "ingress.source",
            ),
        ] {
            let compiled = whipplescript_parser::compile_program(source);
            assert!(
                compiled.diagnostics.is_empty(),
                "{:?}",
                compiled.diagnostics
            );
            let program = compiled.ir.unwrap();
            let mut witness = crate::import_coverage::capture(&program, A, B, C, &[]).unwrap();
            let capture = capture_declarations(&program, &registry, &witness).unwrap();
            assert_eq!(capture.examined.len(), 2);
            assert_eq!(capture.edges.len(), 2);
            assert_eq!(capture.edges[1].registration_id, expected);
            assert_eq!(capture.edges[1].provider_source_digest, C);
            witness.declarations = Some(capture);
            assert!(whipplescript_store::program_imports::encode(&witness).is_ok());

            let mut older = program.clone();
            older.declaration_constructs = None;
            assert!(capture_declarations(&older, &registry, &witness)
                .unwrap_err()
                .contains("no declaration inventory"));
            let mut ambiguous = registry.clone();
            ambiguous.constructs.push(clock.clone());
            if expected == "time.clock_source" {
                assert!(capture_declarations(&program, &ambiguous, &witness)
                    .unwrap_err()
                    .contains("more than one registration"));
            }
            let mut missing = registry.clone();
            missing.constructs.retain(|form| form.id != expected);
            assert!(capture_declarations(&program, &missing, &witness)
                .unwrap_err()
                .contains("unresolved checked declaration"));
            let mut unowned = registry.clone();
            unowned
                .constructs
                .iter_mut()
                .find(|form| form.id == expected)
                .unwrap()
                .library_id = "local.forged".into();
            assert!(capture_declarations(&program, &unowned, &witness)
                .unwrap_err()
                .contains("compiler-owned std library"));
            let mut bad_artifact = witness.clone();
            bad_artifact.compiler_artifact_digest = "not-a-digest".into();
            assert!(capture_declarations(&program, &registry, &bad_artifact)
                .unwrap_err()
                .contains("exact compiler artifact digest"));
            let mut reordered = program.clone();
            reordered
                .declaration_constructs
                .as_mut()
                .unwrap()
                .swap(0, 1);
            assert!(capture_declarations(&reordered, &registry, &witness)
                .unwrap_err()
                .contains("effective-source order"));
        }
    }

    #[test]
    fn checked_empty_declaration_inventory_stays_explicitly_empty() {
        let program = whipplescript_parser::compile_program("workflow Empty")
            .ir
            .expect("checked program");
        let imports = crate::import_coverage::capture(&program, A, B, C, &[]).unwrap();
        let capture = capture_declarations(&program, &ContractRegistry::default(), &imports)
            .expect("new compiler checked an empty declaration population");
        assert!(capture.examined.is_empty());
        assert!(capture.edges.is_empty());
        assert_eq!(capture.edge_digest, sha256_hex(b"[]"));
    }

    #[test]
    fn every_supported_standard_declaration_form_has_a_resolved_edge() {
        let forms = [
            ("coord.lease", "std.coord", "lease"),
            ("coord.ledger", "std.coord", "ledger"),
            ("coord.counter", "std.coord", "counter"),
            ("tracker.tracker", "std.tracker", "tracker"),
            ("files.file_store", "std.files", "file store"),
        ];
        let registry = ContractRegistry {
            libraries: ["std.coord", "std.tracker", "std.files"]
                .into_iter()
                .map(|id| LibraryRegistration {
                    id: id.into(),
                    version: "0.1.0".into(),
                    standard: true,
                })
                .collect(),
            constructs: forms
                .into_iter()
                .map(|(id, library, keyword)| {
                    standard_declaration(id, library, keyword, "declaration_block", "metadata_only")
                })
                .collect(),
            ..ContractRegistry::default()
        };
        for (source, expected) in [
            (
                include_str!("../../../examples/gastown-lite.whip"),
                &["coord.lease", "coord.ledger", "tracker.tracker"][..],
            ),
            (
                include_str!("../../../examples/circuit-breaker.whip"),
                &["coord.counter"][..],
            ),
            (
                include_str!("../../../examples/file-store-demo.whip"),
                &["files.file_store"][..],
            ),
        ] {
            let compiled = whipplescript_parser::compile_program(source);
            assert!(
                compiled.diagnostics.is_empty(),
                "{:?}",
                compiled.diagnostics
            );
            let program = compiled.ir.unwrap();
            let imports = crate::import_coverage::capture(&program, A, B, C, &[]).unwrap();
            let capture = capture_declarations(&program, &registry, &imports).unwrap();
            assert_eq!(
                capture
                    .edges
                    .iter()
                    .map(|edge| edge.registration_id.as_str())
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn construct_capture_binds_unique_std_and_local_registration_sources() {
        let mut program = program();
        let imports = crate::import_coverage::capture(&program, A, B, C, &[]).unwrap();
        let checked = capture(&program, &registry(), &imports, &[]).unwrap();
        assert_eq!(checked.examined.len(), 1);
        assert_eq!(checked.edges[0].registration_id, "messaging.send");
        assert_eq!(checked.edges[0].provider_source_digest, C);
        assert_eq!(
            checked.edges[0].meaning,
            ProgramConstructMeaning::LiveDependency
        );

        let mut duplicate = registry();
        let mut other = duplicate.constructs[0].clone();
        other.id = "other.send".into();
        duplicate.constructs.push(other);
        assert!(capture(&program, &duplicate, &imports, &[])
            .unwrap_err()
            .contains("more than one registration"));
        let empty = ContractRegistry::default();
        assert!(capture(&program, &empty, &imports, &[])
            .unwrap_err()
            .contains("unresolved checked construct"));
        let mut no_contract = registry();
        no_contract.effect_contracts.clear();
        assert!(capture(&program, &no_contract, &imports, &[])
            .unwrap_err()
            .contains("lacks its capability.call effect contract"));
        program.uses.clear();
        assert!(capture(&program, &registry(), &imports, &[])
            .unwrap_err()
            .contains("has no owning std import"));

        program.uses.push(IrUse {
            kind: IrUseKind::Package,
            name: "local.messaging".into(),
        });
        let package = crate::import_coverage::ResolvedLocalPackage {
            name: "local.messaging",
            package_id: "pkg-messaging",
            version: "1",
            source_digest: D,
        };
        let imports = crate::import_coverage::capture(&program, A, B, C, &[package]).unwrap();
        let mut local_registry = registry();
        local_registry.constructs[0].library_id = "local.messaging".into();
        let source = ResolvedConstructSource {
            library_id: "local.messaging",
            package_name: "local.messaging",
            source_digest: D,
        };
        let local = capture(&program, &local_registry, &imports, &[source]).unwrap();
        assert_eq!(local.edges[0].provider_package, "local.messaging");
        assert_eq!(local.edges[0].provider_source_digest, D);
        assert!(capture(&program, &local_registry, &imports, &[])
            .unwrap_err()
            .contains("has no attested package source"));
        assert!(
            capture(&program, &local_registry, &imports, &[source, source])
                .unwrap_err()
                .contains("ambiguous or unbound package source")
        );
        let wrong_package = ResolvedConstructSource {
            package_name: "different",
            ..source
        };
        assert!(
            capture(&program, &local_registry, &imports, &[wrong_package])
                .unwrap_err()
                .contains("ambiguous or unbound package source")
        );
        let bad_digest = ResolvedConstructSource {
            source_digest: "not-a-digest",
            ..source
        };
        let mut bad_imports = imports;
        bad_imports.edges[0].source_digest = "not-a-digest".into();
        assert!(
            capture(&program, &local_registry, &bad_imports, &[bad_digest])
                .unwrap_err()
                .contains("lacks an exact provider source digest")
        );
    }
}
