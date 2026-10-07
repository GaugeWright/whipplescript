//! Current-basis revalidation of a retained declaration edge, read back from
//! both storage implementations. The facade's shipped registry and compiler
//! artifact are the current basis; drift in either makes the edge unknown.
use super::*;
use whipplescript_kernel::construct_revalidation::{
    ConstructEdgeDrift, ConstructEdgeStanding, RetainedConstructStanding,
};
use whipplescript_store::program_imports::ProgramImportWitness;

const COMPILER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MOVED_COMPILER: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn envelope() -> VerifiedEnvelope {
    let signed = SignedEnvelope::from_external_signature_v2(
        "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
        "fixture-signer",
        "fixture",
        "fixture-key",
        "fixture-attestation",
        7,
        "product",
    )
    .expect("policy fixture");
    VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &FixtureAuthority(vec![]))
        .expect("verified policy")
}

/// The shipped standard set without `std.files`: a host that no longer
/// registers the retained declaration.
fn without_files() -> &'static [(&'static str, &'static str)] {
    let kept = whipplescript_host_do::do_packages::EMBEDDED_STD_MANIFESTS
        .iter()
        .copied()
        .filter(|(name, _)| *name != "std.files")
        .collect::<Vec<_>>();
    Box::leak(kept.into_boxed_slice())
}

fn standing_json(standing: &RetainedConstructStanding) -> Value {
    serde_json::to_value(standing).expect("standing")
}

fn journey<S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead>(
    store: S,
) -> Value {
    let source = r#"
workflow ParityDeclaration
input content InputReference
output result Result
file store project {
  root "."
  allow read ["**"]
}
class InputReference { handle string version_ref string label_ref string }
class Result { handle string }
rule echo
  when InputReference as r
=> { complete result { handle r.handle } }
"#;
    let action = CompiledHostAction::compile("reference.declared", source, None)
        .expect("compiled action with declaration");
    let mut facade = GovernedHostFacade::from_verified_store(store, 7, envelope())
        .expect("facade")
        .with_embedded_std_manifests(whipplescript_host_do::do_packages::EMBEDDED_STD_MANIFESTS)
        .with_compiler_artifact_digest(COMPILER);
    let command = HostActionCommand {
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace:1".into(),
        request_id: "action:declared".into(),
        operation: "reference.declared".into(),
        program_version_ref: action.version_ref().into(),
        input_schema_ref: action.input_schema_ref().into(),
        policy: facade.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: "person:1".into(),
            executor: "person:1".into(),
            delegation: vec![],
            origin: "editor.save".into(),
            causes: vec![],
        },
        inputs: BTreeMap::from([(
            "content".into(),
            ActionInput {
                handle: "ledger".into(),
                version_ref: "content:version:1".into(),
                label_ref: "label:private".into(),
            },
        )]),
        resources: BTreeMap::new(),
    };
    let authority = FixtureAuthority(command.signing_bytes().expect("signing bytes"));
    facade
        .admit_action(command, &action, &authority, b"fixture-admission")
        .expect("checked admission");
    let roster = facade
        .kernel()
        .store()
        .program_import_operation_roster()
        .expect("operation roster");
    let operation = roster.operations.last().expect("checked operation");
    let witness: ProgramImportWitness = facade
        .kernel()
        .store()
        .program_import_witness(
            &operation.version_id,
            operation.witness_digest.as_deref().expect("witness digest"),
        )
        .expect("witness lookup")
        .expect("retained witness");
    let declarations = witness
        .declarations
        .as_ref()
        .expect("declarations examined");
    assert_eq!(
        declarations
            .edges
            .iter()
            .map(|edge| edge.registration_id.as_str())
            .collect::<Vec<_>>(),
        ["files.file_store"]
    );

    let current = facade
        .revalidate_retained_constructs(action.program(), &witness)
        .expect("unchanged basis");
    assert!(current.all_current());
    assert_eq!(current.constructs, Some(vec![]));
    assert_eq!(
        current.declarations,
        Some(vec![ConstructEdgeStanding::Current])
    );

    let store = facade.into_kernel().into_store();
    let facade = GovernedHostFacade::from_verified_store(store, 7, envelope())
        .expect("moved compiler facade")
        .with_embedded_std_manifests(whipplescript_host_do::do_packages::EMBEDDED_STD_MANIFESTS)
        .with_compiler_artifact_digest(MOVED_COMPILER);
    let moved_compiler = facade
        .revalidate_retained_constructs(action.program(), &witness)
        .expect("moved compiler judged");
    assert_eq!(
        moved_compiler.declarations,
        Some(vec![ConstructEdgeStanding::Unknown(
            ConstructEdgeDrift::ProviderSourceChanged
        )])
    );
    assert!(!moved_compiler.all_current());

    let store = facade.into_kernel().into_store();
    let facade = GovernedHostFacade::from_verified_store(store, 7, envelope())
        .expect("moved registry facade")
        .with_embedded_std_manifests(without_files())
        .with_compiler_artifact_digest(COMPILER);
    let moved_registry = facade
        .revalidate_retained_constructs(action.program(), &witness)
        .expect("moved registry judged");
    assert_eq!(
        moved_registry.declarations,
        Some(vec![ConstructEdgeStanding::Unknown(
            ConstructEdgeDrift::RegistrationAbsent
        )])
    );

    let store = facade.into_kernel().into_store();
    let unconfigured = GovernedHostFacade::from_verified_store(store, 7, envelope())
        .expect("unconfigured facade")
        .with_compiler_artifact_digest(COMPILER);
    let Err(refusal) = unconfigured.revalidate_retained_constructs(action.program(), &witness)
    else {
        panic!("an unconfigured facade must not judge retained edges");
    };
    assert!(refusal
        .to_string()
        .contains("construct revalidation requires the host's shipped standard registry"));

    json!({
        "current": standing_json(&current),
        "moved_compiler": standing_json(&moved_compiler),
        "moved_registry": standing_json(&moved_registry),
    })
}

#[test]
fn retained_declaration_edges_revalidate_alike_on_native_and_deployed_do_schema() {
    let native = journey(NativeStores::open_in_memory().expect("native stores"));
    let hosted = journey(DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()));
    assert_eq!(native, hosted);
}
