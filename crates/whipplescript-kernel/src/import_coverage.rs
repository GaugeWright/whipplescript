//! The checked-program side of RC-2's bounded local-import witness.
//!
//! This is a pure capture from the compiler's IR and an already resolved local
//! package set. The caller must compute each package's current source digest,
//! supply the exact compiler artifact digest, and write the witness in the same
//! accepting transaction as the program version. This module neither reads a
//! lock file nor asserts that every admitted program used this path.

use std::collections::BTreeMap;

use whipplescript_parser::IrProgram;
pub use whipplescript_store::program_imports::{ProgramImportEdge, ProgramImportWitness};

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
        lock_digest: lock_digest.to_owned(),
        compiler_artifact_digest: compiler_artifact_digest.to_owned(),
        examined: examined.into_iter().map(str::to_owned).collect(),
        edges,
        edge_digest: sha256_hex(&edge_json),
    })
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
    capture(
        program,
        program_source_digest,
        lock_digest,
        compiler_artifact_digest,
        packages,
    )
    .is_ok_and(|fresh| fresh == *witness)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn program(source: &str) -> IrProgram {
        whipplescript_parser::compile_program(source)
            .ir
            .expect("checked program")
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
