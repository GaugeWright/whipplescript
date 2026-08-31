//! Content-identity evidence freshness (DR-0084 Decision 3; modeled by
//! `models/maude/ledger-freshness.maude`, M0 of the knowledge plane).
//!
//! Evidence attests a **basis fingerprint**: the world-denoting region it
//! depends on, resolved at attest time to concrete entries — declaration
//! identities with their canonical hashes, paths with their content hashes.
//! Evidence is FRESH at a frontier iff every entry still matches the
//! frontier's current content, and STALE otherwise. The definition is a pure
//! function of (fingerprint, frontier content): no cut log, no history, no
//! schedule — an edit-then-undo round trip restores freshness, because the
//! tree is what was verified. The since-scan over change-units is witness
//! and attribution only, never the definition.
//!
//! Everything here is pure and host-neutral so the native CLI, the mediator
//! pass, and (later) the DO evaluate identically.

use std::collections::BTreeMap;

use crate::selection::{glob_matches, SelAtom, SelExpr};

/// The frontier's current content, as the two maps a region can denote:
/// declaration identity → canonical hash (DR-0054 canonical print), and
/// path → content hash. Built by the VCS from a branch's head manifest;
/// paths without a canonical form simply contribute no `decls` entries
/// (fail closed — attribution never guesses).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FrontierContent {
    pub decls: BTreeMap<String, String>,
    /// identity → DR-0054 rename hash (the canonical print with the header's
    /// name replaced) — the name-neutral content key the `moved` advisory
    /// compares, since the canonical hash itself covers the header and so
    /// ALWAYS changes across a rename.
    pub decl_renames: BTreeMap<String, String>,
    pub paths: BTreeMap<String, String>,
}

/// Fingerprint keys are namespaced so one map carries every entry kind.
const DECL_PREFIX: &str = "decl:";
const PATH_PREFIX: &str = "path:";
/// Companion entries recording each declaration's name-neutral rename hash
/// at attest time. Not verifiable content (never counted as mismatched) —
/// they exist solely so the `moved` advisory can recognize the recorded
/// content under a new name at a later frontier.
const DECL_RENAME_PREFIX: &str = "decl-rename:";

/// Resolve a world-denoting basis to its fingerprint at a frontier: each
/// `decl(<glob>)` atom contributes every matching identity with its current
/// canonical hash, each `path(<glob>)` every matching path with its content
/// hash, composed under the set operators. Change-set atoms are refused —
/// the same region/change-set split `whip check` enforces on `region`
/// declarations, enforced again here because attest-time basis text can
/// arrive from doors the compiler never saw.
///
/// A basis that resolves to NO entries yields an empty fingerprint, which
/// `evaluate` reads as vacuously fresh — matching the model's empty case.
/// Callers that consider an empty resolution suspicious surface that at
/// their own door.
pub fn resolve_basis(
    expr: &SelExpr,
    frontier: &FrontierContent,
) -> Result<BTreeMap<String, String>, String> {
    match expr {
        SelExpr::Union(a, b) => {
            let mut left = resolve_basis(a, frontier)?;
            left.extend(resolve_basis(b, frontier)?);
            Ok(left)
        }
        SelExpr::Intersect(a, b) => {
            let left = resolve_basis(a, frontier)?;
            let right = resolve_basis(b, frontier)?;
            Ok(left
                .into_iter()
                .filter(|(key, _)| right.contains_key(key))
                .collect())
        }
        SelExpr::Difference(a, b) => {
            let left = resolve_basis(a, frontier)?;
            let right = resolve_basis(b, frontier)?;
            Ok(left
                .into_iter()
                .filter(|(key, _)| !right.contains_key(key))
                .collect())
        }
        SelExpr::Atom(SelAtom::Decl(glob)) => {
            let mut entries: BTreeMap<String, String> = frontier
                .decls
                .iter()
                .filter(|(identity, _)| glob_matches(glob, identity))
                .map(|(identity, hash)| (format!("{DECL_PREFIX}{identity}"), hash.clone()))
                .collect();
            for (identity, rename_hash) in &frontier.decl_renames {
                if glob_matches(glob, identity) {
                    entries.insert(
                        format!("{DECL_RENAME_PREFIX}{identity}"),
                        rename_hash.clone(),
                    );
                }
            }
            Ok(entries)
        }
        SelExpr::Atom(SelAtom::Path(glob)) => Ok(frontier
            .paths
            .iter()
            .filter(|(path, _)| glob_matches(glob, path))
            .map(|(path, hash)| (format!("{PATH_PREFIX}{path}"), hash.clone()))
            .collect()),
        SelExpr::Atom(other) => Err(format!(
            "a basis denotes a part of the artifact world; `{}` is a change-set atom",
            atom_display(other)
        )),
    }
}

fn atom_display(atom: &SelAtom) -> &'static str {
    match atom {
        SelAtom::Path(_) => "path",
        SelAtom::Decl(_) => "decl",
        SelAtom::ByEffect(_) => "by-effect",
        SelAtom::ByOrigin(_) => "by-origin",
        SelAtom::ByActor(_) => "by",
        SelAtom::ByIntent(_) => "intent",
        SelAtom::InBranch(_) => "in-branch",
        SelAtom::Change(_) => "change",
        SelAtom::Cut(_) => "cut",
        SelAtom::Since(_) => "since",
        SelAtom::Until(_) => "until",
        SelAtom::Region(_) => "region",
        SelAtom::DependentsOf(_) => "dependents-of",
    }
}

/// The derived verification status of one keyed fingerprint at a frontier.
/// Never stored — recomputed wherever both arguments are in hand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Freshness {
    /// Every entry matches the frontier's current content (vacuously so for
    /// an empty fingerprint, the model's empty case).
    Fresh,
    /// At least one entry mismatches.
    Stale {
        /// The mismatched fingerprint keys, in order.
        mismatched: Vec<String>,
        /// Rename advisories (DR-0084 Decision 4): for a `decl:` entry whose
        /// identity is ABSENT at the frontier, any frontier identity carrying
        /// the recorded canonical hash — minted from hash equality only,
        /// never from the structural shape of a change. Advisory: the entry
        /// stays mismatched; re-anchoring is always an explicit act.
        moved: Vec<(String, String)>,
    },
}

/// Evaluate a fingerprint against a frontier — the M0 model's verdict
/// function, purity by construction: nothing but these two arguments.
pub fn evaluate(fingerprint: &BTreeMap<String, String>, frontier: &FrontierContent) -> Freshness {
    let mut mismatched = Vec::new();
    let mut moved = Vec::new();
    for (key, recorded) in fingerprint {
        if let Some(identity) = key.strip_prefix(DECL_RENAME_PREFIX) {
            // Companion entry: not verifiable content, only the moved key.
            let _ = (identity, recorded);
        } else if let Some(identity) = key.strip_prefix(DECL_PREFIX) {
            match frontier.decls.get(identity) {
                Some(current) if current == recorded => {}
                Some(_) => mismatched.push(key.clone()),
                None => {
                    mismatched.push(key.clone());
                    // The moved advisory (DR-0084 Decision 4, built form):
                    // the recorded NAME-NEUTRAL canonical content — the
                    // DR-0054 rename hash the companion entry carries —
                    // present at the frontier under a different identity.
                    // Hash equality only, never structural shape.
                    if let Some(recorded_rename) =
                        fingerprint.get(&format!("{DECL_RENAME_PREFIX}{identity}"))
                    {
                        for (candidate, rename_hash) in &frontier.decl_renames {
                            if rename_hash == recorded_rename
                                && !frontier.decls.contains_key(identity)
                                && candidate != identity
                            {
                                moved.push((identity.to_owned(), candidate.clone()));
                            }
                        }
                    }
                }
            }
        } else if let Some(path) = key.strip_prefix(PATH_PREFIX) {
            if frontier.paths.get(path) != Some(recorded) {
                mismatched.push(key.clone());
            }
        } else {
            // An unrecognized key namespace can never be verified against
            // this frontier: mismatched, fail closed.
            mismatched.push(key.clone());
        }
    }
    if mismatched.is_empty() {
        Freshness::Fresh
    } else {
        Freshness::Stale { mismatched, moved }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::parse;

    /// Test frontiers derive each decl's rename hash as `r-<canon>` — the
    /// name-neutral key follows the content, as the real canonicalizer's
    /// rename hash does.
    fn frontier(decls: &[(&str, &str)], paths: &[(&str, &str)]) -> FrontierContent {
        FrontierContent {
            decls: decls
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            decl_renames: decls
                .iter()
                .map(|(k, v)| ((*k).to_owned(), format!("r-{v}")))
                .collect(),
            paths: paths
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    /// Resolution: globs pick matching entries; set operators compose; a
    /// change-set atom in basis position is refused by name.
    #[test]
    fn basis_resolution_composes_and_refuses_change_set_atoms() {
        let front = frontier(
            &[("rule close", "h1"), ("rule open", "h2"), ("class R", "h3")],
            &[("src/a.rs", "p1"), ("docs/b.md", "p2")],
        );
        let expr = parse("decl(rule *) ~ decl(rule open) | path(src/*)").expect("parse");
        let fingerprint = resolve_basis(&expr, &front).expect("resolve");
        assert_eq!(
            fingerprint,
            BTreeMap::from([
                ("decl:rule close".to_owned(), "h1".to_owned()),
                ("decl-rename:rule close".to_owned(), "r-h1".to_owned()),
                ("path:src/a.rs".to_owned(), "p1".to_owned()),
            ])
        );

        let bad = parse("path(src/*) & since(t1)").expect("parse");
        let error = resolve_basis(&bad, &front).expect_err("refused");
        assert!(error.contains("`since` is a change-set atom"), "{error}");
    }

    /// The model's verdict function: fresh on identity, stale on content
    /// change, stale-with-moved on a pure rename (hash equality only), and
    /// PATH-INDEPENDENT — the round-trip frontier equals the attest-time
    /// frontier, so the verdict is fresh again regardless of what happened
    /// in between (the M0 negative fixture, in Rust).
    #[test]
    fn evaluation_is_content_identity_with_the_moved_advisory() {
        let attest_frontier = frontier(&[("rule close", "h1")], &[("src/a.rs", "p1")]);
        let expr = parse("decl(rule close) | path(src/a.rs)").expect("parse");
        let fingerprint = resolve_basis(&expr, &attest_frontier).expect("resolve");

        // Identity: fresh.
        assert_eq!(evaluate(&fingerprint, &attest_frontier), Freshness::Fresh);

        // Content change: stale, no moved advisory.
        let edited = frontier(&[("rule close", "h9")], &[("src/a.rs", "p1")]);
        assert_eq!(
            evaluate(&fingerprint, &edited),
            Freshness::Stale {
                mismatched: vec!["decl:rule close".to_owned()],
                moved: Vec::new(),
            }
        );

        // Round trip: a frontier bit-identical to attest time is fresh again.
        let round_trip = frontier(&[("rule close", "h1")], &[("src/a.rs", "p1")]);
        assert_eq!(evaluate(&fingerprint, &round_trip), Freshness::Fresh);

        // Pure rename: identity gone, the name-neutral content present under
        // a new identity -> moved (the test frontier derives rename hashes
        // from content, so "rule shut" at h1 carries rule close's r-h1).
        let renamed = frontier(&[("rule shut", "h1")], &[("src/a.rs", "p1")]);
        assert_eq!(
            evaluate(&fingerprint, &renamed),
            Freshness::Stale {
                mismatched: vec!["decl:rule close".to_owned()],
                moved: vec![("rule close".to_owned(), "rule shut".to_owned())],
            }
        );

        // Impure rename: identity gone, DIFFERENT hash -> no advisory.
        let impure = frontier(&[("rule shut", "h9")], &[("src/a.rs", "p1")]);
        assert_eq!(
            evaluate(&fingerprint, &impure),
            Freshness::Stale {
                mismatched: vec!["decl:rule close".to_owned()],
                moved: Vec::new(),
            }
        );

        // Empty fingerprint: vacuously fresh (the model's empty case).
        assert_eq!(
            evaluate(&BTreeMap::new(), &attest_frontier),
            Freshness::Fresh
        );
    }
}
