//! Checked rule-effect construct edges for the bounded RC-3 admission slice.
//!
//! The caller supplies the registry and local package-source mapping from the
//! same immutable package snapshot used to check the IR. This pure extractor
//! cannot prove that provenance itself, cover other construct-bearing IR
//! forms, or close a Home operation roster.

use std::collections::BTreeSet;

use whipplescript_core::{ConstructRegistration, ContractRegistry};
use whipplescript_parser::{IrConstructUse, IrProgram};
use whipplescript_store::program_imports::{
    ProgramConstructCapture, ProgramConstructEdge, ProgramConstructMeaning, ProgramConstructScope,
    ProgramConstructUse, ProgramImportWitness,
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

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_core::{std_messaging_send_construct, std_messaging_send_effect_contract};
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

    fn registry() -> ContractRegistry {
        ContractRegistry {
            constructs: vec![std_messaging_send_construct()],
            effect_contracts: vec![std_messaging_send_effect_contract()],
            ..ContractRegistry::default()
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
