//! Reference-coverage premises of a flowing trunk gate (DR-0131 §3, RC-5).
//!
//! A gate certificate's graph coverage is evidence about one exact premise
//! vector: the reference-class registry, the consumer/owner roster, and the
//! source, lock and graph epochs current when the plan was derived. The
//! coverage authority records the current vector here, beside the ref; the
//! final ref transaction compares the certificate's vector with it, so a
//! stale capture, a graph changed after an owner answered, or an `unknown`
//! scope that no owner set can validate refuses admission with the failed
//! premise or scope named.
//!
//! This is owner-routing evidence only. It does not replace source-unit
//! dependency closure: the native candidate still binds every earlier unit of
//! the selected prefix as a predecessor, so an unknown unit edge cannot leave
//! the prefix even when every owner is routed. It also does not compute the
//! graph or route owners (RC-4); a trusted issuer supplies both vectors.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::flowing_admission::FlowingAdmissionRefusal;

/// The single coverage domain this store accounts for: its own Home.
pub const HOME_COVERAGE_DOMAIN: &str = "home";

/// What the authority currently knows about a required scope's population.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowingCoverageUniverse {
    /// Every member is enumerated; the digest names that exact population.
    Closed { members_digest: String },
    /// An enforced ceiling contains every possible missing member.
    Bounded { bound_digest: String },
    /// Neither: an empty edge set over it proves nothing.
    Open,
}

/// One `(edge class, consumer scope)` the registry requires a claim for.
/// `owners` is the roster's owner set for the scope; empty means no owner is
/// identifiable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingRequiredScope {
    pub scope_id: String,
    pub universe: FlowingCoverageUniverse,
    pub owners: Vec<String>,
}

/// The coverage authority's current premise vector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingCoveragePremises {
    pub registry_digest: String,
    pub roster_digest: String,
    pub source_epoch: i64,
    pub lock_epoch: i64,
    pub graph_epoch: i64,
    pub required_scopes: Vec<FlowingRequiredScope>,
}

/// The coverage state a gate plan claims for one scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FlowingCoverageClaim {
    Complete {
        examined_digest: String,
        edge_digest: String,
    },
    Bounded {
        bound_digest: String,
    },
    Unknown,
}

/// An owner's answer that it validated the exact candidate revision against
/// the graph epoch it was shown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingOwnerValidation {
    pub owner: String,
    pub candidate_manifest_hash: String,
    pub graph_epoch: i64,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingScopeCoverage {
    pub scope_id: String,
    pub claim: FlowingCoverageClaim,
    #[serde(default)]
    pub owner_validations: Vec<FlowingOwnerValidation>,
}

/// The premise vector a gate certificate was computed under, with one claim
/// per required scope. `premises_digest` binds the whole recorded vector,
/// including each scope's universe and owner set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingCoverageBasis {
    pub registry_digest: String,
    pub roster_digest: String,
    pub source_epoch: i64,
    pub lock_epoch: i64,
    pub graph_epoch: i64,
    pub premises_digest: String,
    pub scopes: Vec<FlowingScopeCoverage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordCoveragePremisesOutcome {
    Recorded(FlowingCoveragePremises),
    Existing(FlowingCoveragePremises),
    /// An epoch moved backwards, or the vector changed without any premise
    /// identity changing.
    Regressed {
        premise: &'static str,
    },
    Invalid {
        field: &'static str,
    },
}

fn blank(value: &str) -> bool {
    value.trim().is_empty()
}

fn strictly_sorted<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let Some(mut previous) = values.next() else {
        return true;
    };
    for value in values {
        if value <= previous {
            return false;
        }
        previous = value;
    }
    true
}

impl FlowingCoveragePremises {
    pub fn digest(&self) -> crate::StoreResult<String> {
        let bytes = serde_json::to_vec(&("flowing-coverage-premises-v1", self))?;
        Ok(format!(
            "sha256:{}",
            crate::chunking::content_hash_hex(&bytes)
        ))
    }

    pub fn invalid_field(&self) -> Option<&'static str> {
        if blank(&self.registry_digest) {
            return Some("registry_digest");
        }
        if blank(&self.roster_digest) {
            return Some("roster_digest");
        }
        if self.source_epoch < 0 || self.lock_epoch < 0 || self.graph_epoch < 0 {
            return Some("epoch");
        }
        if !strictly_sorted(self.required_scopes.iter().map(|s| s.scope_id.as_str())) {
            return Some("required_scopes");
        }
        for scope in &self.required_scopes {
            let universe_blank = match &scope.universe {
                FlowingCoverageUniverse::Closed { members_digest } => blank(members_digest),
                FlowingCoverageUniverse::Bounded { bound_digest } => blank(bound_digest),
                FlowingCoverageUniverse::Open => false,
            };
            if blank(&scope.scope_id)
                || universe_blank
                || scope.owners.iter().any(|owner| blank(owner))
                || !strictly_sorted(scope.owners.iter().map(String::as_str))
            {
                return Some("required_scopes");
            }
        }
        None
    }

    /// Decide whether `next` may replace `self` as the recorded vector.
    pub fn successor_refusal(&self, next: &Self) -> Option<&'static str> {
        for (premise, before, after) in [
            ("source", self.source_epoch, next.source_epoch),
            ("lock", self.lock_epoch, next.lock_epoch),
            ("graph", self.graph_epoch, next.graph_epoch),
        ] {
            if after < before {
                return Some(premise);
            }
        }
        // A changed scope set, universe or owner set is a new premise vector
        // and must be distinguishable from the old one by its identities.
        if next != self
            && next.registry_digest == self.registry_digest
            && next.roster_digest == self.roster_digest
            && next.source_epoch == self.source_epoch
            && next.lock_epoch == self.lock_epoch
            && next.graph_epoch == self.graph_epoch
        {
            return Some("scopes");
        }
        None
    }
}

impl FlowingCoverageBasis {
    /// The basis a plan derived under `premises` starts from, before any
    /// claim is filled in.
    pub fn under(premises: &FlowingCoveragePremises) -> crate::StoreResult<Self> {
        Ok(Self {
            registry_digest: premises.registry_digest.clone(),
            roster_digest: premises.roster_digest.clone(),
            source_epoch: premises.source_epoch,
            lock_epoch: premises.lock_epoch,
            graph_epoch: premises.graph_epoch,
            premises_digest: premises.digest()?,
            scopes: Vec::new(),
        })
    }

    /// Structural completeness, independent of the current premises.
    pub fn is_well_formed(&self) -> bool {
        if blank(&self.registry_digest)
            || blank(&self.roster_digest)
            || blank(&self.premises_digest)
            || self.source_epoch < 0
            || self.lock_epoch < 0
            || self.graph_epoch < 0
            || !strictly_sorted(self.scopes.iter().map(|s| s.scope_id.as_str()))
        {
            return false;
        }
        self.scopes.iter().all(|scope| {
            let claim_complete = match &scope.claim {
                FlowingCoverageClaim::Complete {
                    examined_digest,
                    edge_digest,
                } => !blank(examined_digest) && !blank(edge_digest),
                FlowingCoverageClaim::Bounded { bound_digest } => !blank(bound_digest),
                FlowingCoverageClaim::Unknown => true,
            };
            !blank(&scope.scope_id)
                && claim_complete
                && strictly_sorted(scope.owner_validations.iter().map(|v| v.owner.as_str()))
                && scope.owner_validations.iter().all(|validation| {
                    !blank(&validation.owner)
                        && !blank(&validation.candidate_manifest_hash)
                        && !blank(&validation.evidence_digest)
                        && validation.graph_epoch >= 0
                })
        })
    }
}

/// Compare a certificate's coverage basis with the current recorded premises
/// for an exact candidate. Called by the gate runner before and after checks
/// and again inside the native and hosted ref transactions.
pub fn check(
    basis: Option<&FlowingCoverageBasis>,
    current: Option<&FlowingCoveragePremises>,
    candidate_manifest_hash: &str,
) -> crate::StoreResult<Result<(), FlowingAdmissionRefusal>> {
    use FlowingAdmissionRefusal as R;

    let (Some(basis), Some(current)) = (basis, current) else {
        // MUTATION-SUCCESS-EXPR: Ok(Ok(()))
        return Ok(Err(R::CoverageUnavailable));
    };
    if !basis.is_well_formed() || current.invalid_field().is_some() {
        // MUTATION-SUCCESS-EXPR: Ok(Ok(()))
        return Ok(Err(R::GatePlanIncomplete));
    }
    for (premise, stale) in [
        ("registry", basis.registry_digest != current.registry_digest),
        ("roster", basis.roster_digest != current.roster_digest),
        ("source", basis.source_epoch != current.source_epoch),
        ("lock", basis.lock_epoch != current.lock_epoch),
        ("graph", basis.graph_epoch != current.graph_epoch),
        ("scopes", basis.premises_digest != current.digest()?),
    ] {
        if stale {
            // MUTATION-SUCCESS-EXPR: Ok(Ok(()))
            return Ok(Err(R::CoverageStale { premise }));
        }
    }
    let required: BTreeSet<&str> = current
        .required_scopes
        .iter()
        .map(|scope| scope.scope_id.as_str())
        .collect();
    if basis
        .scopes
        .iter()
        .any(|claim| !required.contains(claim.scope_id.as_str()))
    {
        // MUTATION-SUCCESS-EXPR: Ok(Ok(()))
        return Ok(Err(R::GatePlanIncomplete));
    }
    for scope in &current.required_scopes {
        let Some(claim) = basis
            .scopes
            .iter()
            .find(|claim| claim.scope_id == scope.scope_id)
        else {
            // A required scope with no record is unknown, never empty.
            let scope_id = scope.scope_id.clone();
            // MUTATION-SUCCESS-EXPR: Ok(Ok(()))
            return Ok(Err(R::CoverageScopeUnknown { scope_id }));
        };
        let routes_every_owner = match (&claim.claim, &scope.universe) {
            // A no-edge or partial query counts only over a closed universe
            // that the issuer actually examined.
            (
                FlowingCoverageClaim::Complete {
                    examined_digest, ..
                },
                FlowingCoverageUniverse::Closed { members_digest },
            ) if examined_digest == members_digest => false,
            (
                FlowingCoverageClaim::Bounded { bound_digest },
                FlowingCoverageUniverse::Bounded {
                    bound_digest: enforced,
                },
            ) if bound_digest == enforced => {
                // The enforced envelope is routed whole.
                true
            }
            _ => true,
        };
        if !routes_every_owner {
            continue;
        }
        if scope.owners.is_empty() {
            // A bound is useful only when its whole possible population has
            // an identifiable owner that can validate this candidate.
            // MUTATION-SUCCESS-EXPR: Ok(Ok(()))
            return Ok(Err(R::CoverageScopeUnknown {
                scope_id: scope.scope_id.clone(),
            }));
        }
        for owner in &scope.owners {
            let validated = claim.owner_validations.iter().any(|validation| {
                &validation.owner == owner
                    && validation.candidate_manifest_hash == candidate_manifest_hash
                    && validation.graph_epoch == current.graph_epoch
            });
            if !validated {
                // MUTATION-SUCCESS-EXPR: Ok(Ok(()))
                return Ok(Err(R::CoverageOwnerUnvalidated {
                    scope_id: scope.scope_id.clone(),
                    owner: owner.clone(),
                }));
            }
        }
    }
    Ok(Ok(()))
}

/// Decide what a trusted premise write does against the recorded vector.
pub fn record_outcome(
    existing: Option<&FlowingCoveragePremises>,
    next: &FlowingCoveragePremises,
) -> RecordCoveragePremisesOutcome {
    if let Some(field) = next.invalid_field() {
        return RecordCoveragePremisesOutcome::Invalid { field };
    }
    match existing {
        Some(existing) if existing == next => {
            RecordCoveragePremisesOutcome::Existing(existing.clone())
        }
        Some(existing) => match existing.successor_refusal(next) {
            Some(premise) => RecordCoveragePremisesOutcome::Regressed { premise },
            None => RecordCoveragePremisesOutcome::Recorded(next.clone()),
        },
        None => RecordCoveragePremisesOutcome::Recorded(next.clone()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use FlowingAdmissionRefusal as R;

    pub(crate) fn premises() -> FlowingCoveragePremises {
        FlowingCoveragePremises {
            registry_digest: "sha256:registry-1".into(),
            roster_digest: "sha256:roster-1".into(),
            source_epoch: 1,
            lock_epoch: 1,
            graph_epoch: 1,
            required_scopes: vec![
                FlowingRequiredScope {
                    scope_id: "imports@home".into(),
                    universe: FlowingCoverageUniverse::Closed {
                        members_digest: "sha256:programs".into(),
                    },
                    owners: vec!["owner-a".into(), "owner-b".into()],
                },
                FlowingRequiredScope {
                    scope_id: "norm-relations@home".into(),
                    universe: FlowingCoverageUniverse::Open,
                    owners: vec!["owner-a".into()],
                },
            ],
        }
    }

    fn validated(owner: &str, candidate: &str, graph_epoch: i64) -> FlowingOwnerValidation {
        FlowingOwnerValidation {
            owner: owner.into(),
            candidate_manifest_hash: candidate.into(),
            graph_epoch,
            evidence_digest: format!("sha256:{owner}-answer"),
        }
    }

    /// A passing basis for `candidate` under `premises`.
    pub(crate) fn basis_for(
        premises: &FlowingCoveragePremises,
        candidate: &str,
    ) -> FlowingCoverageBasis {
        let mut basis = FlowingCoverageBasis::under(premises).unwrap();
        basis.scopes = premises
            .required_scopes
            .iter()
            .map(|scope| match &scope.universe {
                FlowingCoverageUniverse::Closed { members_digest } => FlowingScopeCoverage {
                    scope_id: scope.scope_id.clone(),
                    claim: FlowingCoverageClaim::Complete {
                        examined_digest: members_digest.clone(),
                        edge_digest: "sha256:edges".into(),
                    },
                    owner_validations: Vec::new(),
                },
                _ => FlowingScopeCoverage {
                    scope_id: scope.scope_id.clone(),
                    claim: FlowingCoverageClaim::Unknown,
                    owner_validations: scope
                        .owners
                        .iter()
                        .map(|owner| validated(owner, candidate, premises.graph_epoch))
                        .collect(),
                },
            })
            .collect();
        basis
    }

    fn verdict(
        basis: &FlowingCoverageBasis,
        current: &FlowingCoveragePremises,
    ) -> Result<(), FlowingAdmissionRefusal> {
        check(Some(basis), Some(current), "candidate").unwrap()
    }

    #[test]
    fn exact_premises_admit_and_absence_is_unavailable() {
        let current = premises();
        let basis = basis_for(&current, "candidate");
        assert_eq!(verdict(&basis, &current), Ok(()));
        assert_eq!(
            check(None, Some(&current), "candidate").unwrap(),
            Err(R::CoverageUnavailable)
        );
        assert_eq!(
            check(Some(&basis), None, "candidate").unwrap(),
            Err(R::CoverageUnavailable)
        );
    }

    #[test]
    fn stale_capture_names_the_changed_premise() {
        let captured = premises();
        let basis = basis_for(&captured, "candidate");
        for (premise, change) in [
            (
                "registry",
                (|p: &mut FlowingCoveragePremises| p.registry_digest = "sha256:registry-2".into())
                    as fn(&mut FlowingCoveragePremises),
            ),
            ("roster", |p| p.roster_digest = "sha256:roster-2".into()),
            ("source", |p| p.source_epoch += 1),
            ("lock", |p| p.lock_epoch += 1),
            ("graph", |p| p.graph_epoch += 1),
            ("scopes", |p| p.required_scopes[1].owners.clear()),
        ] {
            let mut current = captured.clone();
            change(&mut current);
            assert_eq!(
                verdict(&basis, &current),
                Err(R::CoverageStale { premise }),
                "{premise}"
            );
        }
    }

    #[test]
    fn graph_changed_after_an_owner_answer_refuses_even_when_recaptured() {
        let before = premises();
        let answered = basis_for(&before, "candidate");
        let mut after = before.clone();
        after.graph_epoch += 1;
        assert_eq!(
            verdict(&answered, &after),
            Err(R::CoverageStale { premise: "graph" })
        );
        // Recapturing the basis does not carry the owner's earlier answer
        // forward to the new graph.
        let mut recaptured = FlowingCoverageBasis::under(&after).unwrap();
        recaptured.scopes = answered.scopes.clone();
        assert_eq!(
            verdict(&recaptured, &after),
            Err(R::CoverageOwnerUnvalidated {
                scope_id: "norm-relations@home".into(),
                owner: "owner-a".into(),
            })
        );
        // An answer about another revision does not validate this one.
        let other = basis_for(&before, "other-candidate");
        assert_eq!(
            verdict(&other, &before),
            Err(R::CoverageOwnerUnvalidated {
                scope_id: "norm-relations@home".into(),
                owner: "owner-a".into(),
            })
        );
    }

    #[test]
    fn no_edge_query_over_an_incomplete_universe_is_unknown() {
        let mut current = premises();
        current.required_scopes[1].owners.clear();
        let mut basis = basis_for(&current, "candidate");
        // The issuer claims an examined, empty edge set over an open roster.
        basis.scopes[1].claim = FlowingCoverageClaim::Complete {
            examined_digest: "sha256:what-the-query-saw".into(),
            edge_digest: "sha256:no-edges".into(),
        };
        assert_eq!(
            verdict(&basis, &current),
            Err(R::CoverageScopeUnknown {
                scope_id: "norm-relations@home".into()
            })
        );
        // Over a closed roster, a query that examined a different population
        // is not complete either; with owners it must route every one.
        let current = premises();
        let mut basis = basis_for(&current, "candidate");
        basis.scopes[0].claim = FlowingCoverageClaim::Complete {
            examined_digest: "sha256:fewer-programs".into(),
            edge_digest: "sha256:no-edges".into(),
        };
        assert_eq!(
            verdict(&basis, &current),
            Err(R::CoverageOwnerUnvalidated {
                scope_id: "imports@home".into(),
                owner: "owner-a".into(),
            })
        );
        basis.scopes[0].owner_validations = vec![
            validated("owner-a", "candidate", 1),
            validated("owner-b", "candidate", 1),
        ];
        assert_eq!(verdict(&basis, &current), Ok(()));
    }

    #[test]
    fn omitted_or_unrequired_scopes_cannot_shrink_the_required_set() {
        let current = premises();
        let mut basis = basis_for(&current, "candidate");
        basis.scopes.remove(1);
        assert_eq!(
            verdict(&basis, &current),
            Err(R::CoverageScopeUnknown {
                scope_id: "norm-relations@home".into()
            })
        );
        let mut basis = basis_for(&current, "candidate");
        basis.scopes.push(FlowingScopeCoverage {
            scope_id: "zz-unrequired".into(),
            claim: FlowingCoverageClaim::Unknown,
            owner_validations: Vec::new(),
        });
        assert_eq!(verdict(&basis, &current), Err(R::GatePlanIncomplete));
        let mut basis = basis_for(&current, "candidate");
        basis.scopes.swap(0, 1);
        assert_eq!(verdict(&basis, &current), Err(R::GatePlanIncomplete));
    }

    #[test]
    fn bounded_scope_routes_its_whole_envelope() {
        let mut current = premises();
        current.required_scopes[1].universe = FlowingCoverageUniverse::Bounded {
            bound_digest: "sha256:ceiling".into(),
        };
        let mut basis = basis_for(&current, "candidate");
        basis.scopes[1].claim = FlowingCoverageClaim::Bounded {
            bound_digest: "sha256:ceiling".into(),
        };
        assert_eq!(verdict(&basis, &current), Ok(()));
        basis.scopes[1].owner_validations.clear();
        assert_eq!(
            verdict(&basis, &current),
            Err(R::CoverageOwnerUnvalidated {
                scope_id: "norm-relations@home".into(),
                owner: "owner-a".into(),
            })
        );
        // Even an enforced bound cannot route a possible missing member if
        // the authority has no owner to ask.
        current.required_scopes[1].owners.clear();
        let mut basis = basis_for(&current, "candidate");
        basis.scopes[1].claim = FlowingCoverageClaim::Bounded {
            bound_digest: "sha256:ceiling".into(),
        };
        assert_eq!(
            verdict(&basis, &current),
            Err(R::CoverageScopeUnknown {
                scope_id: "norm-relations@home".into()
            })
        );
        // An unenforced bound is also unknown without an owner.
        basis.scopes[1].claim = FlowingCoverageClaim::Bounded {
            bound_digest: "sha256:other-ceiling".into(),
        };
        assert_eq!(
            verdict(&basis, &current),
            Err(R::CoverageScopeUnknown {
                scope_id: "norm-relations@home".into()
            })
        );
    }

    #[test]
    fn premise_writes_are_monotonic_and_identified() {
        let first = premises();
        assert!(matches!(
            record_outcome(None, &first),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
        assert!(matches!(
            record_outcome(Some(&first), &first),
            RecordCoveragePremisesOutcome::Existing(_)
        ));
        let mut regressed = first.clone();
        regressed.graph_epoch = 0;
        assert_eq!(
            record_outcome(Some(&first), &regressed),
            RecordCoveragePremisesOutcome::Regressed { premise: "graph" }
        );
        let mut silent = first.clone();
        silent.required_scopes[0].owners.pop();
        assert_eq!(
            record_outcome(Some(&first), &silent),
            RecordCoveragePremisesOutcome::Regressed { premise: "scopes" }
        );
        silent.roster_digest = "sha256:roster-2".into();
        assert!(matches!(
            record_outcome(Some(&first), &silent),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
        let mut invalid = first.clone();
        invalid.required_scopes.swap(0, 1);
        assert_eq!(
            record_outcome(None, &invalid),
            RecordCoveragePremisesOutcome::Invalid {
                field: "required_scopes"
            }
        );
    }
}
