//! WS-159 (RC-2): every version-admitting store operation records a checked
//! import witness or an explicit lack of one, on the native and hosted stores
//! alike, and current-basis revalidation reads a second uncaptured program or
//! a same-lock package source change as unknown, never complete.
use std::collections::BTreeSet;

use whipplescript_kernel::import_coverage::{
    self, CurrentImportBasis, CurrentLocalPackage, ImportCoverage, ImportCoverageGap,
    ResolvedLocalPackage,
};
use whipplescript_store::program_imports::admission_inventory::{
    admitting_functions, enclosing_functions, item_body, production_source, reached_only_from,
    OPERATION_ROW_WRITE, VERSION_ADMITTING_OPERATIONS, VERSION_ROW_WRITES,
};
use whipplescript_store::program_imports::{ProgramImportOperationKind, ProgramImportWitness};
use whipplescript_store::*;

const LOCK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const COMPILER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const NEXT_COMPILER: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const PAINT_SOURCE: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const CHANGED_PAINT_SOURCE: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// One checked program: its source, IR and the 128-bit native-style source id
/// (a prefix of the full digest, which both stores accept).
struct Program {
    name: &'static str,
    source_digest: String,
    source_id: String,
    ir: whipplescript_parser::IrProgram,
}

fn program(name: &'static str, source: &str) -> Program {
    let source_digest = whipplescript_store::items::sha256_hex(source);
    Program {
        name,
        source_id: source_digest[..32].to_owned(),
        source_digest,
        ir: whipplescript_parser::compile_program(source)
            .ir
            .expect("checked fixture program"),
    }
}

fn paint() -> Program {
    program("paint", "use local.paint\nworkflow Paint\n")
}

fn version<'a>(program: &'a Program, ir_hash: &'a str) -> NewProgramVersion<'a> {
    NewProgramVersion {
        program_name: program.name,
        source_hash: &program.source_id,
        ir_hash,
        compiler_version: "inventory",
        ir_snapshot: None,
        declared_capabilities_json: "[]",
        declared_profiles_json: "[]",
        declared_skills_json: "[]",
        declared_schemas_json: "[]",
        analysis_summary_json: "{}",
        generated_artifacts_json: "[]",
        artifact_root: None,
    }
}

fn packages(paint_source: &str) -> Vec<CurrentLocalPackage> {
    vec![CurrentLocalPackage {
        name: "local.paint".into(),
        package_id: "pkg-paint".into(),
        version: "1".into(),
        source_digest: paint_source.into(),
    }]
}

fn basis(program: &Program, compiler: &str, paint_source: &str) -> CurrentImportBasis {
    CurrentImportBasis {
        program: program.ir.clone(),
        program_source_digest: program.source_digest.clone(),
        version_source_digest: None,
        lock_digest: LOCK.into(),
        compiler_artifact_digest: compiler.into(),
        packages: if program.ir.uses.is_empty() {
            Vec::new()
        } else {
            packages(paint_source)
        },
        construct_basis: None,
    }
}

fn witness(program: &Program, compiler: &str, paint_source: &str) -> ProgramImportWitness {
    let packages = packages(paint_source);
    let resolved: Vec<_> = packages
        .iter()
        .map(|package| ResolvedLocalPackage {
            name: &package.name,
            package_id: &package.package_id,
            version: &package.version,
            source_digest: &package.source_digest,
        })
        .collect();
    let used = if program.ir.uses.is_empty() {
        &resolved[..0]
    } else {
        &resolved[..]
    };
    import_coverage::capture(&program.ir, &program.source_digest, LOCK, compiler, used)
        .expect("fixture witness")
}

fn operation_id(seed: u8) -> String {
    format!("imp_{}", format!("{seed:02x}").repeat(16))
}

/// Call one classified method on a store holding an instance of `paint`
/// admitted at `COMPILER`, and return the version and operation it reports.
fn admit_through<S: RuntimeStore>(
    store: &mut S,
    method: &str,
    paint: &Program,
    instance_id: &str,
) -> (String, Option<String>) {
    let checked = witness(paint, COMPILER, PAINT_SOURCE);
    let reattested = witness(paint, NEXT_COMPILER, PAINT_SOURCE);
    match method {
        "create_program_version" => {
            let record = store
                .create_program_version(version(paint, COMPILER))
                .expect("plain admission");
            (record.version_id, None)
        }
        "create_program_version_with_import_witness" => {
            let record = store
                .create_program_version_with_import_witness(version(paint, COMPILER), &checked)
                .expect("checked admission");
            (record.version_id, Some(record.operation_id))
        }
        "create_program_version_with_import_witness_at_id" => {
            let id = operation_id(0x1a);
            let record = store
                .create_program_version_with_import_witness_at_id(
                    version(paint, COMPILER),
                    &checked,
                    &id,
                )
                .expect("checked admission at a Home id");
            assert_eq!(record.operation_id, id);
            (record.version_id, Some(record.operation_id))
        }
        "reattest_instance_program" => {
            let record = store
                .reattest_instance_program(instance_id, version(paint, NEXT_COMPILER))
                .expect("plain re-attestation");
            (record.version_id, None)
        }
        "reattest_instance_program_with_import_witness" => {
            let record = store
                .reattest_instance_program_with_import_witness(
                    instance_id,
                    version(paint, NEXT_COMPILER),
                    &reattested,
                )
                .expect("checked re-attestation");
            (record.version_id, Some(record.operation_id))
        }
        "reattest_instance_program_with_import_witness_at_id" => {
            let id = operation_id(0x2b);
            let record = store
                .reattest_instance_program_with_import_witness_at_id(
                    instance_id,
                    version(paint, NEXT_COMPILER),
                    &reattested,
                    &id,
                )
                .expect("checked re-attestation at a Home id");
            assert_eq!(record.operation_id, id);
            (record.version_id, Some(record.operation_id))
        }
        unclassified => panic!(
            "`{unclassified}` admits a program version but this inventory cannot exercise it"
        ),
    }
}

/// Every classified method records exactly one operation of its declared
/// kind, and a checked one names a witness the store can read back.
fn every_admitting_operation_records_its_declared_kind<S: RuntimeStore>(
    mut fresh: impl FnMut() -> S,
) {
    let paint = paint();
    for operation in VERSION_ADMITTING_OPERATIONS {
        let mut store = fresh();
        let seed = store
            .create_program_version_with_import_witness(
                version(&paint, COMPILER),
                &witness(&paint, COMPILER, PAINT_SOURCE),
            )
            .expect("seed admission");
        let instance = store
            .create_instance(NewInstance {
                program_id: &seed.program_id,
                version_id: &seed.version_id,
                input_json: "{}",
            })
            .expect("seed instance");
        let before = store.program_import_operation_roster().unwrap();
        let (version_id, reported) =
            admit_through(&mut store, operation.method, &paint, &instance.instance_id);
        let after = store.program_import_operation_roster().unwrap();
        assert_eq!(
            after.operations.len(),
            before.operations.len() + 1,
            "`{}` must record exactly one accepting operation",
            operation.method
        );
        assert!(after.frontier > before.frontier);
        let recorded = after.operations.last().unwrap();
        assert_eq!(recorded.version_id, version_id, "{}", operation.method);
        assert_eq!(recorded.kind, operation.records, "{}", operation.method);
        if let Some(reported) = reported {
            assert_eq!(recorded.operation_id, reported, "{}", operation.method);
        }
        match &recorded.kind {
            ProgramImportOperationKind::Checked => {
                let digest = recorded.witness_digest.as_deref().expect("checked digest");
                assert!(
                    store
                        .program_import_witness(&version_id, digest)
                        .unwrap()
                        .is_some(),
                    "`{}` recorded a witness it cannot read back",
                    operation.method
                );
            }
            ProgramImportOperationKind::Unwitnessed => {
                assert!(recorded.witness_digest.is_none());
            }
            ProgramImportOperationKind::LegacyGap => {
                panic!("`{}` must not record a legacy gap", operation.method)
            }
        }
    }
}

#[test]
fn native_admitting_operations_record_their_declared_kind() {
    every_admitting_operation_records_its_declared_kind(|| {
        SqliteStore::open_in_memory().expect("native store")
    });
}

#[test]
fn hosted_admitting_operations_record_their_declared_kind() {
    every_admitting_operation_records_its_declared_kind(crate::do_store::test_support::store);
}

/// The hosted store has no version-admitting method or raw version write
/// that the shared inventory does not classify.
#[test]
fn hosted_store_admits_versions_only_through_classified_operations() {
    let classified: BTreeSet<&str> = VERSION_ADMITTING_OPERATIONS
        .iter()
        .map(|operation| operation.method)
        .collect();
    let store = production_source(include_str!("do_store.rs"));
    let implemented: BTreeSet<String> = admitting_functions(
        item_body(
            &store,
            "impl<Sql: DoSql> RuntimeStore for DoSqliteStore<Sql>",
        )
        .expect("hosted RuntimeStore impl"),
        false,
    )
    .into_iter()
    .collect();
    assert_eq!(
        implemented,
        classified.iter().map(|name| (*name).to_owned()).collect(),
        "every hosted method that admits a program version must be classified"
    );
    assert!(
        admitting_functions(&store, true).is_empty(),
        "a public hosted admission method outside RuntimeStore is unclassified"
    );
    let writers: BTreeSet<String> = VERSION_ROW_WRITES
        .iter()
        .flat_map(|write| enclosing_functions(&store, write))
        .collect();
    assert_eq!(
        writers,
        BTreeSet::from(["do_insert_program_version".to_owned()]),
        "a raw hosted program version write is outside the classified writer"
    );
    reached_only_from(
        &store,
        "do_insert_program_version",
        &classified,
        &mut BTreeSet::new(),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let recorders: BTreeSet<String> = enclosing_functions(&store, OPERATION_ROW_WRITE)
        .into_iter()
        .collect();
    for caller in enclosing_functions(&store, "do_insert_program_version(") {
        if caller != "do_insert_program_version" {
            assert!(
                recorders.contains(&caller),
                "`{caller}` writes a hosted version without recording its operation"
            );
        }
    }
    for (name, source) in [
        ("lib.rs", include_str!("lib.rs")),
        ("do_worker.rs", include_str!("do_worker.rs")),
        ("do_fork.rs", include_str!("do_fork.rs")),
        ("do_instance.rs", include_str!("do_instance.rs")),
        ("do_packages.rs", include_str!("do_packages.rs")),
        (
            "do_store/host_actions.rs",
            include_str!("do_store/host_actions.rs"),
        ),
        ("do_store/recovery.rs", include_str!("do_store/recovery.rs")),
        (
            "do_store/transaction.rs",
            include_str!("do_store/transaction.rs"),
        ),
    ] {
        let production = production_source(source);
        for write in VERSION_ROW_WRITES {
            assert!(
                enclosing_functions(&production, write).is_empty(),
                "{name} writes program versions outside the classified writer"
            );
        }
    }
}

fn gaps(coverage: ImportCoverage) -> Vec<ImportCoverageGap> {
    match coverage {
        ImportCoverage::Unknown { gaps, .. } => gaps,
        complete => panic!("expected unknown coverage, read {complete:?}"),
    }
}

/// Revalidation over one store: a current witness is complete; a same-lock
/// package source change, a changed compiler, a second program admitted
/// without a witness, or a witnessed program with no current basis is
/// unknown.
fn current_basis_revalidation<S: RuntimeStore>(mut fresh: impl FnMut() -> S) {
    let paint = paint();
    let sketch = program("sketch", "workflow Sketch\n");

    let mut store = fresh();
    assert_eq!(
        import_coverage::revalidate(&store, |_| None).unwrap(),
        ImportCoverage::Complete {
            frontier: 0,
            operations: 0
        }
    );
    let first = store
        .create_program_version_with_import_witness(
            version(&paint, COMPILER),
            &witness(&paint, COMPILER, PAINT_SOURCE),
        )
        .unwrap();
    let current = |paint_source: &'static str, compiler: &'static str| {
        let paint = &paint;
        let sketch = &sketch;
        move |view: &ProgramVersionView| match view.program_name.as_str() {
            "paint" => Some(basis(paint, compiler, paint_source)),
            "sketch" => Some(basis(sketch, compiler, paint_source)),
            _ => None,
        }
    };
    let roster = store.program_import_operation_roster().unwrap();
    assert_eq!(
        import_coverage::revalidate(&store, current(PAINT_SOURCE, COMPILER)).unwrap(),
        ImportCoverage::Complete {
            frontier: roster.frontier,
            operations: 1
        }
    );

    // The lock digest is unchanged; only the package's source bytes moved.
    let same_lock =
        gaps(import_coverage::revalidate(&store, current(CHANGED_PAINT_SOURCE, COMPILER)).unwrap());
    assert_eq!(
        same_lock,
        vec![ImportCoverageGap::Stale {
            operation_id: first.operation_id.clone(),
            version_id: first.version_id.clone(),
            witness_digest: first.witness_digest.clone(),
        }]
    );
    assert!(matches!(
        gaps(import_coverage::revalidate(&store, current(PAINT_SOURCE, NEXT_COMPILER)).unwrap())
            .as_slice(),
        [ImportCoverageGap::Stale { .. }]
    ));

    // A second program admitted without a witness keeps coverage unknown
    // even while the first program's witness is current.
    let uncaptured = store
        .create_program_version(version(&sketch, COMPILER))
        .unwrap();
    let after_second = store.program_import_operation_roster().unwrap();
    let selected = import_coverage::revalidate_selected(
        &store,
        std::slice::from_ref(&first.operation_id),
        current(PAINT_SOURCE, COMPILER),
    )
    .unwrap();
    assert_eq!(selected.frontier, after_second.frontier);
    assert_eq!(selected.selected, after_second.operations[..1]);
    assert_eq!(selected.outside, after_second.operations[1..]);
    assert!(selected.gaps.is_empty());
    assert_eq!(
        import_coverage::revalidate_selected(
            &store,
            std::slice::from_ref(&first.operation_id),
            current(CHANGED_PAINT_SOURCE, COMPILER),
        )
        .unwrap()
        .gaps,
        same_lock
    );
    assert_eq!(
        import_coverage::revalidate_selected(&store, &["missing-from-target".into()], |_| panic!(
            "an absent selected operation has no version to recapture"
        ),)
        .unwrap()
        .gaps,
        vec![ImportCoverageGap::MissingOperation {
            operation_id: "missing-from-target".into(),
        }]
    );
    assert!(import_coverage::revalidate_selected(
        &store,
        &[first.operation_id.clone(), first.operation_id.clone()],
        current(PAINT_SOURCE, COMPILER),
    )
    .is_err());
    assert_eq!(
        gaps(import_coverage::revalidate(&store, current(PAINT_SOURCE, COMPILER)).unwrap()),
        vec![ImportCoverageGap::Unwitnessed {
            operation_id: store
                .program_import_operation_roster()
                .unwrap()
                .operations
                .last()
                .unwrap()
                .operation_id
                .clone(),
            version_id: uncaptured.version_id.clone(),
        }]
    );

    // A later unwitnessed acceptance of the already witnessed version is not
    // repaired by that version's valid witness.
    let mut reused = fresh();
    let witnessed = reused
        .create_program_version_with_import_witness(
            version(&paint, COMPILER),
            &witness(&paint, COMPILER, PAINT_SOURCE),
        )
        .unwrap();
    let again = reused
        .create_program_version(version(&paint, COMPILER))
        .unwrap();
    assert_eq!(again.version_id, witnessed.version_id);
    let reused_roster = reused.program_import_operation_roster().unwrap();
    let reused_selected = import_coverage::revalidate_selected(
        &reused,
        std::slice::from_ref(&witnessed.operation_id),
        current(PAINT_SOURCE, COMPILER),
    )
    .unwrap();
    assert!(reused_selected.gaps.is_empty());
    assert_eq!(reused_selected.selected, reused_roster.operations[..1]);
    assert_eq!(reused_selected.outside, reused_roster.operations[1..]);
    assert!(matches!(
        gaps(import_coverage::revalidate(&reused, current(PAINT_SOURCE, COMPILER)).unwrap())
            .as_slice(),
        [ImportCoverageGap::Unwitnessed { version_id, .. }] if *version_id == witnessed.version_id
    ));

    // A second witnessed program the caller cannot re-check is unknown too.
    let mut unrecapturable = fresh();
    unrecapturable
        .create_program_version_with_import_witness(
            version(&paint, COMPILER),
            &witness(&paint, COMPILER, PAINT_SOURCE),
        )
        .unwrap();
    let second = unrecapturable
        .create_program_version_with_import_witness(
            version(&sketch, COMPILER),
            &witness(&sketch, COMPILER, PAINT_SOURCE),
        )
        .unwrap();
    assert_eq!(
        import_coverage::revalidate(&unrecapturable, current(PAINT_SOURCE, COMPILER)).unwrap(),
        ImportCoverage::Complete {
            frontier: unrecapturable
                .program_import_operation_roster()
                .unwrap()
                .frontier,
            operations: 2
        }
    );
    assert_eq!(
        gaps(
            import_coverage::revalidate(&unrecapturable, |view: &ProgramVersionView| {
                (view.program_name == "paint").then(|| basis(&paint, COMPILER, PAINT_SOURCE))
            })
            .unwrap()
        ),
        vec![ImportCoverageGap::NoCurrentBasis {
            operation_id: second.operation_id,
            version_id: second.version_id,
        }]
    );
}

#[test]
fn native_current_basis_revalidation_never_reads_drift_as_complete() {
    current_basis_revalidation(|| SqliteStore::open_in_memory().expect("native store"));
}

#[test]
fn hosted_current_basis_revalidation_never_reads_drift_as_complete() {
    current_basis_revalidation(crate::do_store::test_support::store);
}
