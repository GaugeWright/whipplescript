//! The checked-program side of RC-2's bounded local-import witness.
//!
//! This is a pure capture from the compiler's IR and an already resolved local
//! package set. The caller must compute each package's current source digest,
//! supply the exact compiler artifact digest, and write the witness in the same
//! accepting transaction as the program version. This module neither reads a
//! lock file nor asserts that every admitted program used this path.
//!
//! `revalidate` reads one store's accepting-operation roster and recaptures
//! each checked witness from the caller's current basis. Any unwitnessed,
//! legacy, unreadable, unrecapturable or stale operation keeps that store's
//! coverage unknown (WS-159). `revalidate_selected` checks the exact operation
//! IDs in a sealed Home cut and returns every operation outside it for the
//! Home to account for separately.

use std::collections::{BTreeMap, BTreeSet};

use whipplescript_parser::IrProgram;
pub use whipplescript_store::program_imports::{ProgramImportEdge, ProgramImportWitness};
use whipplescript_store::program_imports::{ProgramImportOperation, ProgramImportOperationKind};
use whipplescript_store::{ProgramVersionView, RuntimeStore, StoreError, StoreResult};

/// Explicit no-lock basis for hosts that admit only std imports.
pub const NO_LOCK_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

use crate::exec_http::sha256_hex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedLocalPackage<'a> {
    pub name: &'a str,
    pub package_id: &'a str,
    pub version: &'a str,
    /// Digest of the source bytes relevant to this package, freshly read at
    /// capture/verification time; v0's lock digest alone does not cover them.
    pub source_digest: &'a str,
}

/// Exact inputs captured from the same checked source and resolved package
/// snapshot that produced the IR. The admitting caller owns that snapshot;
/// this type does not claim the rest of the Home used the same boundary.
pub struct CheckedImportBasis<'a> {
    pub program_source_digest: &'a str,
    /// Version source id when it covers a checked composite identity that
    /// contains this exact source, rather than the source bytes alone.
    pub version_source_digest: Option<&'a str>,
    pub lock_digest: &'a str,
    pub compiler_artifact_digest: &'a str,
    pub packages: &'a [ResolvedLocalPackage<'a>],
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Refuse an incomplete or ambiguous capture. The witness remains scoped to
/// this program and import class until an authoritative program roster proves
/// that every other admitted program has a current witness too.
pub fn capture(
    program: &IrProgram,
    program_source_digest: &str,
    lock_digest: &str,
    compiler_artifact_digest: &str,
    packages: &[ResolvedLocalPackage<'_>],
) -> Result<ProgramImportWitness, String> {
    for (label, value) in [
        ("program source", program_source_digest),
        ("package lock", lock_digest),
        ("compiler artifact", compiler_artifact_digest),
    ] {
        if !is_digest(value) {
            return Err(format!(
                "{label} must have an exact lowercase SHA-256 digest"
            ));
        }
    }
    let mut by_name = BTreeMap::new();
    for package in packages {
        if !is_digest(package.source_digest) {
            return Err(format!(
                "package `{}` lacks an exact source digest",
                package.name
            ));
        }
        if by_name.contains_key(package.name) {
            return Err(format!(
                "package `{}` resolves more than once",
                package.name
            ));
        }
        by_name.insert(package.name, package);
    }
    let examined = program
        .uses
        .iter()
        .map(|use_decl| use_decl.name.as_str())
        .filter(|name| *name != "std" && !name.starts_with("std."))
        .collect::<std::collections::BTreeSet<_>>();
    let mut edges = Vec::with_capacity(examined.len());
    for name in &examined {
        let package = by_name
            .get(name)
            .ok_or_else(|| format!("unresolved local package import `{name}`"))?;
        edges.push(ProgramImportEdge {
            import: (*name).to_owned(),
            package_id: package.package_id.to_owned(),
            version: package.version.to_owned(),
            source_digest: package.source_digest.to_owned(),
        });
    }
    let edge_json = serde_json::to_vec(&edges).map_err(|error| error.to_string())?;
    Ok(ProgramImportWitness {
        program_source_digest: program_source_digest.to_owned(),
        version_source_digest: None,
        lock_digest: lock_digest.to_owned(),
        compiler_artifact_digest: compiler_artifact_digest.to_owned(),
        examined: examined.into_iter().map(str::to_owned).collect(),
        edges,
        edge_digest: sha256_hex(&edge_json),
        constructs: None,
        declarations: None,
        package_calls: Some(crate::construct_coverage::capture_package_calls(program)?),
        provider_bindings: Some(crate::provider_coverage::capture(program)?),
        resource_fields: Some(crate::resource_coverage::capture(program)?),
    })
}

pub fn capture_basis(
    program: &IrProgram,
    basis: &CheckedImportBasis<'_>,
) -> Result<ProgramImportWitness, String> {
    let mut witness = capture(
        program,
        basis.program_source_digest,
        basis.lock_digest,
        basis.compiler_artifact_digest,
        basis.packages,
    )?;
    if let Some(version_source) = basis.version_source_digest {
        if !is_digest(version_source) {
            return Err("version source must have an exact lowercase SHA-256 digest".into());
        }
        witness.version_source_digest = Some(version_source.to_owned());
    }
    Ok(witness)
}

/// Re-examine current source bytes, lock, compiler and resolved packages. A
/// same-name package source change invalidates the witness even if v0's lock
/// digest and manifest are unchanged.
pub fn current(
    witness: &ProgramImportWitness,
    program: &IrProgram,
    program_source_digest: &str,
    lock_digest: &str,
    compiler_artifact_digest: &str,
    packages: &[ResolvedLocalPackage<'_>],
) -> bool {
    current_basis(
        witness,
        program,
        &CheckedImportBasis {
            program_source_digest,
            version_source_digest: None,
            lock_digest,
            compiler_artifact_digest,
            packages,
        },
    )
}

/// Revalidate a checked admission that may use a composite host-version
/// source identity. A current check must recapture both source identities from
/// the same immutable program/package snapshot as the checked IR.
pub fn current_basis(
    witness: &ProgramImportWitness,
    program: &IrProgram,
    basis: &CheckedImportBasis<'_>,
) -> bool {
    capture_basis(program, basis).is_ok_and(|fresh| fresh == *witness)
}

/// One local package as the caller resolves it now, with a freshly read
/// source digest. Owned so a revalidation callback can return it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentLocalPackage {
    pub name: String,
    pub package_id: String,
    pub version: String,
    pub source_digest: String,
}

/// One currently resolved provider for a checked construct. The caller must
/// read this mapping from the same current package snapshot as `packages`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentConstructSource {
    pub library_id: String,
    pub package_name: String,
    pub source_digest: String,
}

/// Current registry and provider sources, rather than captures copied from an
/// admitted witness. Revalidation derives both construct classes from these
/// inputs and the current IR.
#[derive(Clone, Debug)]
pub struct CurrentConstructBasis {
    pub registry: whipplescript_core::ContractRegistry,
    pub sources: Vec<CurrentConstructSource>,
}

/// A program version's current inputs, recaptured at revalidation time from
/// one immutable snapshot: the checked IR, the source bytes it was checked
/// from, the lock in force, the running compiler artifact and every resolved
/// local package. Nothing here may be copied from the stored witness; a basis
/// read back from the evidence it is meant to test would always agree with it.
#[derive(Clone, Debug)]
pub struct CurrentImportBasis {
    pub program: IrProgram,
    pub program_source_digest: String,
    pub version_source_digest: Option<String>,
    pub lock_digest: String,
    pub compiler_artifact_digest: String,
    pub packages: Vec<CurrentLocalPackage>,
    /// Current registry and provider mapping when the admission captured
    /// construct/declaration edges. Absence cannot revalidate either class.
    pub construct_basis: Option<CurrentConstructBasis>,
}

impl CurrentImportBasis {
    fn recapture(&self) -> Result<ProgramImportWitness, String> {
        let packages = self
            .packages
            .iter()
            .map(|package| ResolvedLocalPackage {
                name: &package.name,
                package_id: &package.package_id,
                version: &package.version,
                source_digest: &package.source_digest,
            })
            .collect::<Vec<_>>();
        let mut witness = capture_basis(
            &self.program,
            &CheckedImportBasis {
                program_source_digest: &self.program_source_digest,
                version_source_digest: self.version_source_digest.as_deref(),
                lock_digest: &self.lock_digest,
                compiler_artifact_digest: &self.compiler_artifact_digest,
                packages: &packages,
            },
        )?;
        if let Some(construct_basis) = &self.construct_basis {
            let sources = construct_basis
                .sources
                .iter()
                .map(
                    |source| crate::construct_coverage::ResolvedConstructSource {
                        library_id: &source.library_id,
                        package_name: &source.package_name,
                        source_digest: &source.source_digest,
                    },
                )
                .collect::<Vec<_>>();
            witness.constructs = Some(crate::construct_coverage::capture(
                &self.program,
                &construct_basis.registry,
                &witness,
                &sources,
            )?);
            witness.declarations = Some(crate::construct_coverage::capture_declarations(
                &self.program,
                &construct_basis.registry,
                &witness,
            )?);
        }
        Ok(witness)
    }
}

/// Why one accepting operation keeps a store's import coverage unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImportCoverageGap {
    /// The sealed Home cut named an operation absent from this target store.
    MissingOperation { operation_id: String },
    /// The operation admitted a version and recorded that it has no witness.
    Unwitnessed {
        operation_id: String,
        version_id: String,
    },
    /// The version predates the operation ledger; its past calls are lost.
    LegacyGap {
        operation_id: String,
        version_id: String,
    },
    /// A checked row whose witness or version can no longer be read back.
    MissingEvidence {
        operation_id: String,
        version_id: String,
    },
    /// No current basis could be recaptured for this program version, for
    /// example a program the caller does not know how to re-check.
    NoCurrentBasis {
        operation_id: String,
        version_id: String,
    },
    /// The current basis recaptures a different witness: changed source,
    /// lock, compiler, package source under an unchanged lock, or imports.
    Stale {
        operation_id: String,
        version_id: String,
        witness_digest: String,
    },
}

/// One runtime store's import coverage at the roster frontier it read.
///
/// `Complete` says only that every operation this store recorded up to
/// `frontier` is checked and that its witness equals a fresh capture from the
/// caller's current basis. It is not a Home-wide claim: a Home has several
/// stores, and operations after the frontier are not covered by this answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImportCoverage {
    Complete {
        frontier: i64,
        operations: usize,
    },
    Unknown {
        frontier: i64,
        gaps: Vec<ImportCoverageGap>,
    },
}

/// Evidence for one exact selection of a store's accepting operations.
///
/// This deliberately has no `Complete` case. The Home must bind `selected` to
/// its sealed journal cut, account for `outside` as later admissions or gaps,
/// and retain the Home use door through its final ref comparison. An empty
/// `gaps` alone cannot establish any of those Home-wide obligations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedImportCoverage {
    pub frontier: i64,
    pub selected: Vec<ProgramImportOperation>,
    pub outside: Vec<ProgramImportOperation>,
    pub gaps: Vec<ImportCoverageGap>,
}

/// Revalidate exactly the operation identities named by a sealed Home cut.
/// The roster read also exposes later target-store operations, so a caller
/// cannot silently treat a checked subset as the whole target population.
/// Missing selected identities are gaps; repeated identities in the request
/// are refused because a seal is a set of operations.
pub fn revalidate_selected<S, F>(
    store: &S,
    selected_ids: &[String],
    mut current: F,
) -> StoreResult<SelectedImportCoverage>
where
    S: RuntimeStore + ?Sized,
    F: FnMut(&ProgramVersionView) -> Option<CurrentImportBasis>,
{
    let requested = selected_ids.iter().cloned().collect::<BTreeSet<_>>();
    if requested.len() != selected_ids.len() {
        return Err(StoreError::Conflict(
            "sealed import operation selection contains duplicate identities".into(),
        ));
    }
    let roster = store.program_import_operation_roster()?;
    let mut selected = Vec::new();
    let mut outside = Vec::new();
    for operation in roster.operations {
        if requested.contains(&operation.operation_id) {
            selected.push(operation);
        } else {
            outside.push(operation);
        }
    }
    let observed = selected
        .iter()
        .map(|operation| operation.operation_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut gaps = requested
        .iter()
        .filter(|id| !observed.contains(id.as_str()))
        .map(|id| ImportCoverageGap::MissingOperation {
            operation_id: id.clone(),
        })
        .collect::<Vec<_>>();
    gaps.extend(revalidate_rows(store, &selected, &mut current)?);
    Ok(SelectedImportCoverage {
        frontier: roster.frontier,
        selected,
        outside,
        gaps,
    })
}

/// Revalidate every recorded accepting operation in one store against the
/// current basis. `current` is asked once per program version and must
/// recapture that version's inputs now; returning `None` leaves every
/// operation on the version unknown. An unwitnessed or legacy operation is
/// never repaired by a valid witness on the same version, because the
/// version row alone does not say which acceptance used which basis.
pub fn revalidate<S, F>(store: &S, mut current: F) -> StoreResult<ImportCoverage>
where
    S: RuntimeStore + ?Sized,
    F: FnMut(&ProgramVersionView) -> Option<CurrentImportBasis>,
{
    let roster = store.program_import_operation_roster()?;
    let gaps = revalidate_rows(store, &roster.operations, &mut current)?;
    Ok(if gaps.is_empty() {
        ImportCoverage::Complete {
            frontier: roster.frontier,
            operations: roster.operations.len(),
        }
    } else {
        ImportCoverage::Unknown {
            frontier: roster.frontier,
            gaps,
        }
    })
}

fn revalidate_rows<S, F>(
    store: &S,
    operations: &[ProgramImportOperation],
    current: &mut F,
) -> StoreResult<Vec<ImportCoverageGap>>
where
    S: RuntimeStore + ?Sized,
    F: FnMut(&ProgramVersionView) -> Option<CurrentImportBasis>,
{
    let mut recaptured: BTreeMap<String, Option<ProgramImportWitness>> = BTreeMap::new();
    let mut gaps = Vec::new();
    for operation in operations {
        let operation_id = operation.operation_id.clone();
        let version_id = operation.version_id.clone();
        let witness_digest = match (&operation.kind, &operation.witness_digest) {
            (ProgramImportOperationKind::Checked, Some(digest)) => digest,
            (ProgramImportOperationKind::LegacyGap, _) => {
                gaps.push(ImportCoverageGap::LegacyGap {
                    operation_id,
                    version_id,
                });
                continue;
            }
            _ => {
                gaps.push(ImportCoverageGap::Unwitnessed {
                    operation_id,
                    version_id,
                });
                continue;
            }
        };
        let Some(stored) = store.program_import_witness(&version_id, witness_digest)? else {
            gaps.push(ImportCoverageGap::MissingEvidence {
                operation_id,
                version_id,
            });
            continue;
        };
        if !recaptured.contains_key(&version_id) {
            let fresh = match store.get_program_version(&version_id)? {
                Some(view) => current(&view).and_then(|basis| basis.recapture().ok()),
                None => {
                    gaps.push(ImportCoverageGap::MissingEvidence {
                        operation_id,
                        version_id,
                    });
                    continue;
                }
            };
            recaptured.insert(version_id.clone(), fresh);
        }
        match &recaptured[&version_id] {
            None => gaps.push(ImportCoverageGap::NoCurrentBasis {
                operation_id,
                version_id,
            }),
            Some(fresh) if *fresh == stored => {}
            Some(_) => gaps.push(ImportCoverageGap::Stale {
                operation_id,
                version_id,
                witness_digest: witness_digest.clone(),
            }),
        }
    }
    Ok(gaps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_core::{
        std_messaging_send_construct, std_messaging_send_effect_contract, ContractRegistry,
    };

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn program(source: &str) -> IrProgram {
        whipplescript_parser::compile_program(source)
            .ir
            .expect("checked program")
    }

    #[cfg(feature = "native")]
    #[test]
    fn sealed_selection_refuses_a_duplicate_operation_identity() {
        let store = whipplescript_store::SqliteStore::open_in_memory().expect("store");
        assert!(matches!(
            revalidate_selected(&store, &["same".into(), "same".into()], |_| None),
            Err(StoreError::Conflict(message)) if message.contains("duplicate identities")
        ));
    }

    #[test]
    fn current_construct_edges_are_derived_from_the_current_registry() {
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
        let basis = CurrentImportBasis {
            program: program(source),
            program_source_digest: sha256_hex(source.as_bytes()),
            version_source_digest: None,
            lock_digest: NO_LOCK_DIGEST.into(),
            compiler_artifact_digest: C.into(),
            packages: vec![],
            construct_basis: Some(CurrentConstructBasis {
                registry: ContractRegistry {
                    constructs: vec![std_messaging_send_construct()],
                    effect_contracts: vec![std_messaging_send_effect_contract()],
                    ..ContractRegistry::default()
                },
                sources: vec![],
            }),
        };
        let admitted = basis.recapture().expect("current construct basis");
        assert_eq!(admitted.constructs.as_ref().unwrap().edges.len(), 1);
        assert!(admitted.declarations.is_some());

        let mut changed = basis.clone();
        changed
            .construct_basis
            .as_mut()
            .unwrap()
            .registry
            .constructs[0]
            .version = "0.2.0".into();
        assert_ne!(
            changed.recapture().expect("changed registry is resolvable"),
            admitted
        );

        changed
            .construct_basis
            .as_mut()
            .unwrap()
            .registry
            .constructs
            .clear();
        assert!(changed.recapture().is_err());

        changed.construct_basis = None;
        let unproven = changed.recapture().expect("import-only basis");
        assert!(unproven.constructs.is_none());
        assert!(unproven.declarations.is_none());
        assert_ne!(unproven, admitted);
    }

    #[test]
    fn composite_version_basis_requires_an_exact_digest() {
        let ir = program("workflow Checked\n");
        let basis = CheckedImportBasis {
            program_source_digest: A,
            version_source_digest: Some("not-a-digest"),
            lock_digest: B,
            compiler_artifact_digest: C,
            packages: &[],
        };
        assert!(capture_basis(&ir, &basis)
            .unwrap_err()
            .contains("version source must have an exact lowercase SHA-256 digest"));
    }

    #[test]
    fn composite_version_currentness_requires_both_source_identities() {
        let ir = program("use local.x\nworkflow Checked\n");
        let package = ResolvedLocalPackage {
            name: "local.x",
            package_id: "pkg-x",
            version: "1",
            source_digest: A,
        };
        let basis = CheckedImportBasis {
            program_source_digest: A,
            version_source_digest: Some(B),
            lock_digest: C,
            compiler_artifact_digest: D,
            packages: &[package],
        };
        let witness = capture_basis(&ir, &basis).expect("composite witness");
        assert!(current_basis(&witness, &ir, &basis));
        assert!(!current(&witness, &ir, A, C, D, &[package]));
        assert!(!current_basis(
            &witness,
            &ir,
            &CheckedImportBasis {
                version_source_digest: Some(A),
                ..basis
            }
        ));
        assert!(!current_basis(
            &witness,
            &ir,
            &CheckedImportBasis {
                program_source_digest: B,
                ..basis
            }
        ));
        let changed_source = ResolvedLocalPackage {
            source_digest: B,
            ..package
        };
        assert!(!current_basis(
            &witness,
            &ir,
            &CheckedImportBasis {
                packages: &[changed_source],
                ..basis
            }
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn checked_compiled_admission_persists_the_extracted_imports_with_the_version() {
        let source = "use local.x\nworkflow Imports\n";
        let ir = program(source);
        let program_source_digest = sha256_hex(source.as_bytes());
        let package_source_digest = sha256_hex(b"checked package source");
        let packages = [ResolvedLocalPackage {
            name: "local.x",
            package_id: "pkg-x",
            version: "1",
            source_digest: &package_source_digest,
        }];
        let basis = CheckedImportBasis {
            program_source_digest: &program_source_digest,
            version_source_digest: None,
            lock_digest: A,
            compiler_artifact_digest: B,
            packages: &packages,
        };
        let mut kernel = crate::RuntimeKernel::new(
            whipplescript_store::SqliteStore::open_in_memory().expect("store"),
        );
        let input = crate::CompiledProgramVersionInput {
            program_name: &ir.workflow,
            source_hash: &crate::stable_hash_hex(source),
            compiler_version: "test",
        };
        let admitted = kernel
            .create_program_version_for_compiled_program_with_imports(
                input, &ir, None, &basis, None,
            )
            .expect("admitted");
        let stored = kernel
            .store()
            .program_import_witness(&admitted.version_id, &admitted.witness_digest)
            .expect("read witness")
            .expect("witness");
        assert_eq!(
            stored,
            capture(&ir, &program_source_digest, A, B, &packages).unwrap()
        );
        assert!(stored
            .package_calls
            .as_ref()
            .is_some_and(|capture| capture.examined.is_empty()));
        assert!(stored
            .provider_bindings
            .as_ref()
            .is_some_and(|capture| capture.examined.is_empty()));
        assert!(stored
            .resource_fields
            .as_ref()
            .is_some_and(|capture| capture.examined.is_empty()));
        assert!(kernel
            .store()
            .get_program_version(&admitted.version_id)
            .expect("read version")
            .is_some());

        let missing = CheckedImportBasis {
            packages: &[],
            ..basis
        };
        assert!(matches!(
            kernel.create_program_version_for_compiled_program_with_imports(
                input, &ir, None, &missing, None
            ),
            Err(whipplescript_store::StoreError::Conflict(message))
                if message.contains("unresolved local package import")
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn checked_native_admission_persists_and_revalidates_resource_fields() {
        use whipplescript_store::program_imports::ProgramResourceField;

        let source = include_str!("../../../examples/file-store-demo.whip");
        let ir = program(source);
        let source_digest = sha256_hex(source.as_bytes());
        let basis = CheckedImportBasis {
            program_source_digest: &source_digest,
            version_source_digest: None,
            lock_digest: NO_LOCK_DIGEST,
            compiler_artifact_digest: B,
            packages: &[],
        };
        let mut kernel = crate::RuntimeKernel::new(
            whipplescript_store::SqliteStore::open_in_memory().expect("store"),
        );
        let admitted = kernel
            .create_program_version_for_compiled_program_with_imports(
                crate::CompiledProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: &crate::stable_hash_hex(source),
                    compiler_version: "test",
                },
                &ir,
                None,
                &basis,
                None,
            )
            .expect("checked admission");
        let stored = kernel
            .store()
            .program_import_witness(&admitted.version_id, &admitted.witness_digest)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored
                .resource_fields
                .as_ref()
                .unwrap()
                .examined
                .iter()
                .filter(|field| field.owner == "notes_store")
                .count(),
            3
        );
        assert!(stored
            .resource_fields
            .as_ref()
            .unwrap()
            .examined
            .iter()
            .any(|use_site| use_site.field == ProgramResourceField::FileStoreRoot));
        assert!(current_basis(&stored, &ir, &basis));
        let mut changed = ir;
        changed.file_stores[0].root = "./different-root".into();
        assert!(!current_basis(&stored, &changed, &basis));
    }

    #[cfg(feature = "native")]
    #[test]
    fn checked_native_admission_revalidates_agent_skill_selectors() {
        use whipplescript_store::program_imports::{
            ProgramResourceField, ProgramResourceFieldScope,
        };

        let source = include_str!("../../../examples/revision-ticket-v1.whip");
        let ir = program(source);
        let source_digest = sha256_hex(source.as_bytes());
        let basis = CheckedImportBasis {
            program_source_digest: &source_digest,
            version_source_digest: None,
            lock_digest: NO_LOCK_DIGEST,
            compiler_artifact_digest: B,
            packages: &[],
        };
        let mut kernel = crate::RuntimeKernel::new(
            whipplescript_store::SqliteStore::open_in_memory().expect("store"),
        );
        let admitted = kernel
            .create_program_version_for_compiled_program_with_imports(
                crate::CompiledProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: &crate::stable_hash_hex(source),
                    compiler_version: "test",
                },
                &ir,
                None,
                &basis,
                None,
            )
            .expect("checked admission");
        let stored = kernel
            .store()
            .program_import_witness(&admitted.version_id, &admitted.witness_digest)
            .unwrap()
            .unwrap();
        let fields = stored.resource_fields.as_ref().unwrap();
        assert_eq!(
            fields.scope,
            ProgramResourceFieldScope::DeclaredFieldsAgentEffectAndTurnAccessV5
        );
        assert!(fields.examined.iter().any(|field| {
            field.owner == "worker"
                && field.field == ProgramResourceField::AgentSkills
                && field.values == ["whipplescript-author"]
        }));
        assert!(current_basis(&stored, &ir, &basis));
        let mut changed = ir;
        changed
            .agents
            .iter_mut()
            .find(|agent| agent.name == "worker")
            .unwrap()
            .skills
            .clear();
        assert!(!current_basis(&stored, &changed, &basis));
    }

    #[cfg(feature = "native")]
    #[test]
    fn checked_native_admission_revalidates_turn_access_narrowing() {
        use whipplescript_store::program_imports::ProgramResourceField;

        let source = include_str!("../../../examples/least-privilege-subagent.whip");
        let compiled = whipplescript_parser::compile_program_with_root(source, Some("ReviewDocs"));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let ir = compiled.ir.unwrap();
        let source_digest = sha256_hex(source.as_bytes());
        let basis = CheckedImportBasis {
            program_source_digest: &source_digest,
            version_source_digest: None,
            lock_digest: NO_LOCK_DIGEST,
            compiler_artifact_digest: B,
            packages: &[],
        };
        let mut kernel = crate::RuntimeKernel::new(
            whipplescript_store::SqliteStore::open_in_memory().expect("store"),
        );
        let admitted = kernel
            .create_program_version_for_compiled_program_with_imports(
                crate::CompiledProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: &crate::stable_hash_hex(source),
                    compiler_version: "test",
                },
                &ir,
                None,
                &basis,
                None,
            )
            .expect("checked admission");
        let stored = kernel
            .store()
            .program_import_witness(&admitted.version_id, &admitted.witness_digest)
            .unwrap()
            .unwrap();
        assert!(stored
            .resource_fields
            .as_ref()
            .unwrap()
            .examined
            .iter()
            .any(|field| {
                field.field == ProgramResourceField::EffectTurnAccessGrants
                    && !field.values.is_empty()
            }));
        assert!(current_basis(&stored, &ir, &basis));
        let mut changed = ir;
        let grant = changed
            .rules
            .iter_mut()
            .flat_map(|rule| &mut rule.metadata.effects)
            .flat_map(|effect| &mut effect.access_grants)
            .next()
            .unwrap();
        grant.operations[0].globs = vec!["private/**".into()];
        assert!(!current_basis(&stored, &changed, &basis));
    }

    #[cfg(feature = "native")]
    #[test]
    fn checked_native_admission_revalidates_mint_endpoint_and_parent() {
        use whipplescript_store::program_imports::ProgramResourceField;

        let source = r#"
@service
workflow MintEgress

use std.custody
use std.ingress

credential stripe_api { kind bearer }
signal charge.disputed { note string }
output result R
class R { v string }

rule scoped
  when charge.disputed as charge
=> {
  mint credential from stripe_api {
    at POST "https://connect.stripe.com/oauth/token"
    header "Authorization" basic stripe_api
    body "grant_type=client_credentials"
    token at "access_token"
  } as token
  after token succeeds { complete result { v "minted" } }
}
"#;
        let ir = program(source);
        let source_digest = sha256_hex(source.as_bytes());
        let basis = CheckedImportBasis {
            program_source_digest: &source_digest,
            version_source_digest: None,
            lock_digest: NO_LOCK_DIGEST,
            compiler_artifact_digest: B,
            packages: &[],
        };
        let mut kernel = crate::RuntimeKernel::new(
            whipplescript_store::SqliteStore::open_in_memory().expect("store"),
        );
        let admitted = kernel
            .create_program_version_for_compiled_program_with_imports(
                crate::CompiledProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: &crate::stable_hash_hex(source),
                    compiler_version: "test",
                },
                &ir,
                None,
                &basis,
                None,
            )
            .expect("checked admission");
        let stored = kernel
            .store()
            .program_import_witness(&admitted.version_id, &admitted.witness_digest)
            .unwrap()
            .unwrap();
        let fields = &stored.resource_fields.as_ref().unwrap().examined;
        assert!(fields.iter().any(|field| {
            field.field == ProgramResourceField::EffectMintParent && field.values == ["stripe_api"]
        }));
        assert!(current_basis(&stored, &ir, &basis));
        let mut changed_capability = ir.clone();
        changed_capability
            .rules
            .iter_mut()
            .flat_map(|rule| rule.metadata.effects.iter_mut())
            .find(|effect| effect.mint_credential.is_some())
            .unwrap()
            .required_capabilities
            .push("new.capability".into());
        assert!(!current_basis(&stored, &changed_capability, &basis));
        let mut changed = ir;
        let mint = changed
            .rules
            .iter_mut()
            .flat_map(|rule| rule.metadata.effects.iter_mut())
            .find_map(|effect| effect.mint_credential.as_mut())
            .unwrap();
        mint.exchange.url = "https://other.invalid/token".into();
        assert!(!current_basis(&stored, &changed, &basis));
    }

    #[test]
    fn exact_imports_and_same_lock_source_drift() {
        let ir = program("use std.memory\nuse local.x\nuse local.y\nworkflow Imports\n");
        let x = ResolvedLocalPackage {
            name: "local.x",
            package_id: "pkg-x",
            version: "1",
            source_digest: A,
        };
        let y = ResolvedLocalPackage {
            name: "local.y",
            package_id: "pkg-y",
            version: "2",
            source_digest: B,
        };
        let witness = capture(&ir, C, D, A, &[x, y]).expect("all imports resolved");
        assert_eq!(witness.examined, vec!["local.x", "local.y"]);
        assert_eq!(witness.edges.len(), 2);
        assert!(current(&witness, &ir, C, D, A, &[x, y]));
        let changed_y = ResolvedLocalPackage {
            source_digest: C,
            ..y
        };
        assert!(!current(&witness, &ir, C, D, A, &[x, changed_y]));
        assert!(!current(&witness, &ir, B, D, A, &[x, y]));
        assert!(!current(&witness, &ir, C, B, A, &[x, y]));
        assert!(!current(&witness, &ir, C, D, B, &[x, y]));
        assert!(capture(&ir, C, D, A, &[x]).is_err());
        assert!(capture(&ir, C, D, A, &[x, x, y]).is_err());
        let later_import =
            program("use std.memory\nuse local.x\nuse local.y\nuse local.z\nworkflow Imports\n");
        assert!(!current(&witness, &later_import, C, D, A, &[x, y]));
    }

    #[test]
    fn malformed_exact_basis_and_package_source_refuse_capture() {
        let ir = program("use local.x\nworkflow Imports\n");
        let valid = ResolvedLocalPackage {
            name: "local.x",
            package_id: "pkg-x",
            version: "1",
            source_digest: A,
        };
        for (source, lock, compiler, label) in [
            ("short", B, C, "program source"),
            (A, "short", C, "package lock"),
            (A, B, "short", "compiler artifact"),
            (&A.to_uppercase(), B, C, "program source"),
        ] {
            let error = capture(&ir, source, lock, compiler, &[valid])
                .expect_err("malformed basis must not produce a witness");
            assert!(error.contains(label), "{error}");
        }
        let invalid_source = ResolvedLocalPackage {
            source_digest: "short",
            ..valid
        };
        let error = capture(&ir, A, B, C, &[invalid_source])
            .expect_err("package source without exact digest must refuse");
        assert!(error.contains("lacks an exact source digest"), "{error}");
    }
}
