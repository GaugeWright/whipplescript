use super::*;
use crate::construct_coverage::{
    capture, capture_declarations, embedded_std_registry_for_program, TEST_SHIPPED_STD_MANIFESTS,
};
use whipplescript_parser::IrProgram;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

const CURRENT: ConstructEdgeStanding = ConstructEdgeStanding::Current;

fn unknown(drift: ConstructEdgeDrift) -> ConstructEdgeStanding {
    ConstructEdgeStanding::Unknown(drift)
}

/// One rule-effect construct (`send`) and one declaration (`file store`), both
/// resolved from the shipped standard set exactly as an admission does.
fn admitted() -> (IrProgram, ContractRegistry, ProgramImportWitness) {
    let source = r##"use std.messaging
workflow Notify
file store project {
  root "."
  allow read ["**"]
}
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
    let program = compiled.ir.unwrap();
    let registry = embedded_std_registry_for_program(&program, TEST_SHIPPED_STD_MANIFESTS)
        .expect("shipped registry");
    let mut witness = crate::import_coverage::capture(&program, A, B, C, &[]).unwrap();
    witness.constructs = Some(capture(&program, &registry, &witness, &[]).unwrap());
    witness.declarations = Some(capture_declarations(&program, &registry, &witness).unwrap());
    assert_eq!(witness.constructs.as_ref().unwrap().edges.len(), 1);
    assert_eq!(witness.declarations.as_ref().unwrap().edges.len(), 1);
    (program, registry, witness)
}

fn judge(witness: &ProgramImportWitness, registry: &ContractRegistry) -> RetainedConstructStanding {
    revalidate(
        witness,
        &CurrentConstructBasis {
            registry,
            compiler_artifact_digest: C,
            sources: &[],
        },
    )
    .expect("judged")
}

fn reseal(witness: &mut ProgramImportWitness) {
    if let Some(capture) = witness.constructs.as_mut() {
        capture.edge_digest = sha256_hex(&serde_json::to_vec(&capture.edges).unwrap());
    }
    if let Some(capture) = witness.declarations.as_mut() {
        capture.edge_digest = sha256_hex(&serde_json::to_vec(&capture.edges).unwrap());
    }
}

#[test]
fn unchanged_basis_keeps_every_retained_edge_current() {
    let (_, registry, witness) = admitted();
    let standing = judge(&witness, &registry);
    assert_eq!(standing.constructs, Some(vec![CURRENT]));
    assert_eq!(standing.declarations, Some(vec![CURRENT]));
    assert!(standing.all_current());
}

#[test]
fn compiler_artifact_drift_makes_std_edges_unknown() {
    let (_, registry, witness) = admitted();
    let standing = revalidate(
        &witness,
        &CurrentConstructBasis {
            registry: &registry,
            compiler_artifact_digest: D,
            sources: &[],
        },
    )
    .unwrap();
    let drift = unknown(ConstructEdgeDrift::ProviderSourceChanged);
    assert_eq!(standing.constructs, Some(vec![drift]));
    assert_eq!(standing.declarations, Some(vec![drift]));
    assert!(!standing.all_current());
}

#[test]
fn registry_drift_makes_the_affected_edge_unknown_and_never_reresolves_it() {
    let (_, registry, witness) = admitted();
    let send = witness.constructs.as_ref().unwrap().edges[0]
        .registration_id
        .clone();
    let declared = witness.declarations.as_ref().unwrap().edges[0]
        .registration_id
        .clone();

    // Absent: the shipped set no longer registers the construct.
    let mut absent = registry.clone();
    absent.constructs.retain(|form| form.id != send);
    let standing = judge(&witness, &absent);
    assert_eq!(
        standing.constructs,
        Some(vec![unknown(ConstructEdgeDrift::RegistrationAbsent)])
    );
    assert_eq!(standing.declarations, Some(vec![CURRENT]));

    // Ambiguous: two current registrations share the retained id.
    let mut ambiguous = registry.clone();
    let duplicate = ambiguous
        .constructs
        .iter()
        .find(|form| form.id == declared)
        .unwrap()
        .clone();
    ambiguous.constructs.push(duplicate);
    assert_eq!(
        judge(&witness, &ambiguous).declarations,
        Some(vec![unknown(ConstructEdgeDrift::RegistrationAmbiguous)])
    );

    // Changed: a newer version is a different registration, not this edge.
    let changed_drift = Some(vec![unknown(ConstructEdgeDrift::RegistrationChanged)]);
    type Mutation = fn(&mut ConstructRegistration);
    let mutations: [(&str, Mutation); 6] = [
        ("version", |form| form.version = "9.9.9".into()),
        ("library", |form| form.library_id = "std.forged".into()),
        ("keyword", |form| form.keyword = "forged".into()),
        ("scope", |form| form.scope = "forged".into()),
        ("family", |form| form.construct_family = "forged".into()),
        ("lowering", |form| form.lowering_target = "forged".into()),
    ];
    for (field, mutate) in mutations {
        for id in [&send, &declared] {
            let mut moved = registry.clone();
            mutate(
                moved
                    .constructs
                    .iter_mut()
                    .find(|form| &form.id == id)
                    .unwrap(),
            );
            let standing = judge(&witness, &moved);
            let class = if id == &send {
                &standing.constructs
            } else {
                &standing.declarations
            };
            assert_eq!(class, &changed_drift, "{field} drift on {id}");
        }
    }

    // A capability moving onto a declaration, or off a rule effect, moves it.
    let mut capable = registry.clone();
    capable
        .constructs
        .iter_mut()
        .find(|form| form.id == declared)
        .unwrap()
        .target_capability = Some("forged".into());
    assert_eq!(judge(&witness, &capable).declarations, changed_drift);
    let mut incapable = registry.clone();
    incapable
        .constructs
        .iter_mut()
        .find(|form| form.id == send)
        .unwrap()
        .target_capability = None;
    assert_eq!(judge(&witness, &incapable).constructs, changed_drift);

    // The construct's effect contract is part of what it resolved to.
    let capability = witness.constructs.as_ref().unwrap().edges[0]
        .use_form
        .capability
        .clone();
    let mut uncontracted = registry.clone();
    uncontracted
        .effect_contracts
        .retain(|contract| contract.id != capability);
    assert_eq!(
        judge(&witness, &uncontracted).constructs,
        Some(vec![unknown(ConstructEdgeDrift::EffectContractAbsent)])
    );
}

#[test]
fn package_provider_edges_need_the_same_current_source() {
    let (_, mut registry, mut witness) = admitted();
    let edge = &mut witness.constructs.as_mut().unwrap().edges[0];
    edge.library_id = "local.notify".into();
    edge.provider_package = "local.notify".into();
    edge.provider_source_digest = A.into();
    let id = edge.registration_id.clone();
    registry
        .constructs
        .iter_mut()
        .find(|form| form.id == id)
        .unwrap()
        .library_id = "local.notify".into();
    reseal(&mut witness);
    let judge_with = |sources: &[ResolvedConstructSource<'_>]| {
        revalidate(
            &witness,
            &CurrentConstructBasis {
                registry: &registry,
                compiler_artifact_digest: C,
                sources,
            },
        )
        .unwrap()
        .constructs
    };
    let same = ResolvedConstructSource {
        library_id: "local.notify",
        package_name: "local.notify",
        source_digest: A,
    };
    assert_eq!(judge_with(&[same]), Some(vec![CURRENT]));
    assert_eq!(
        judge_with(&[]),
        Some(vec![unknown(ConstructEdgeDrift::ProviderSourceUnavailable)])
    );
    assert_eq!(
        judge_with(&[same, same]),
        Some(vec![unknown(ConstructEdgeDrift::ProviderSourceAmbiguous)])
    );
    let moved = ResolvedConstructSource {
        source_digest: B,
        ..same
    };
    assert_eq!(
        judge_with(&[moved]),
        Some(vec![unknown(ConstructEdgeDrift::ProviderSourceChanged)])
    );
    let renamed = ResolvedConstructSource {
        package_name: "local.other",
        ..same
    };
    assert_eq!(
        judge_with(&[renamed]),
        Some(vec![unknown(ConstructEdgeDrift::ProviderSourceUnavailable)])
    );
}

#[test]
fn a_std_edge_naming_another_provider_is_not_current() {
    let (_, registry, mut witness) = admitted();
    witness.declarations.as_mut().unwrap().edges[0].provider_package = "std.forged".into();
    reseal(&mut witness);
    assert_eq!(
        judge(&witness, &registry).declarations,
        Some(vec![unknown(ConstructEdgeDrift::ProviderSourceChanged)])
    );
}

#[test]
fn unknown_classes_stay_unknown_and_examined_empty_is_current() {
    let (_, registry, mut witness) = admitted();
    witness.constructs = None;
    let standing = judge(&witness, &registry);
    assert_eq!(standing.constructs, None);
    assert_eq!(standing.declarations, Some(vec![CURRENT]));
    assert!(!standing.all_current());

    let (_, registry, mut witness) = admitted();
    for capture in witness.declarations.iter_mut() {
        capture.edges.clear();
        capture.examined.clear();
    }
    reseal(&mut witness);
    let standing = judge(&witness, &registry);
    assert_eq!(standing.declarations, Some(vec![]));
    assert!(standing.all_current());
}

#[test]
fn a_tampered_witness_or_inexact_basis_is_refused_rather_than_judged() {
    let (_, registry, witness) = admitted();
    let mut tampered = witness.clone();
    tampered.constructs.as_mut().unwrap().edges[0].registration_version = "9.9.9".into();
    assert!(revalidate(
        &tampered,
        &CurrentConstructBasis {
            registry: &registry,
            compiler_artifact_digest: C,
            sources: &[],
        },
    )
    .unwrap_err()
    .contains("construct edges do not match their digest"));
    let mut tampered = witness.clone();
    tampered.declarations.as_mut().unwrap().edges[0].registration_version = "9.9.9".into();
    assert!(revalidate(
        &tampered,
        &CurrentConstructBasis {
            registry: &registry,
            compiler_artifact_digest: C,
            sources: &[],
        },
    )
    .unwrap_err()
    .contains("declaration edges do not match their digest"));
    for bad in ["", "not-a-digest", &C.to_uppercase()] {
        assert!(revalidate(
            &witness,
            &CurrentConstructBasis {
                registry: &registry,
                compiler_artifact_digest: bad,
                sources: &[],
            },
        )
        .unwrap_err()
        .contains("exact compiler artifact digest"));
    }
}
