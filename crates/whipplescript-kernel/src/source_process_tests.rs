use super::*;
use std::cell::Cell;

fn version(name: &str) -> EvidenceVersion {
    EvidenceVersion {
        name: name.into(),
        version: "1".into(),
        digest: format!("digest:{name}"),
    }
}
fn dep(name: &str) -> DependencyIdentity {
    DependencyIdentity {
        authority: "home".into(),
        identity: name.into(),
    }
}
fn scope() -> ReferenceScope {
    ReferenceScope {
        class: version("imports"),
        consumer_scope: "programs".into(),
    }
}
struct Authority {
    basis: ProcessBasis,
    observations: BTreeMap<(CutSide, ReferenceScope), ScopeObservation>,
    boundary: VerifiedScopeBoundary,
    fallback: bool,
    missing_owner: Option<DependencyIdentity>,
    change_on_recapture: bool,
    reads: Cell<usize>,
}
impl Authority {
    fn new() -> Self {
        let cut = |name: &str, provider: &str| StructuralCut {
            cut: name.into(),
            registry: version("registry"),
            population: version("roster"),
            resolutions: BTreeMap::from([
                (dep("provider"), provider.into()),
                (dep("a"), "a1".into()),
                (dep("b"), "b1".into()),
            ]),
            scopes: BTreeMap::from([(scope(), BTreeSet::from([dep("a"), dep("b")]))]),
        };
        let basis = ProcessBasis {
            home: "home".into(),
            candidate_witness_digest: "candidate".into(),
            native_base_cut: None,
            native_candidate_cut: "candidate-cut".into(),
            seal: version("seal"),
            policy: version("policy"),
            before: cut("before", "old"),
            after: cut("after", "new"),
        };
        let observations = [
            (CutSide::Before, &basis.before),
            (CutSide::After, &basis.after),
        ]
        .into_iter()
        .map(|(side, cut)| {
            let live = BTreeSet::from([
                LiveDependency {
                    consumer: dep("a"),
                    consumer_revision: "a1".into(),
                    provider: dep("provider"),
                    provider_revision: cut.resolutions[&dep("provider")].clone(),
                },
                LiveDependency {
                    consumer: dep("b"),
                    consumer_revision: "b1".into(),
                    provider: dep("a"),
                    provider_revision: "a1".into(),
                },
            ]);
            (
                (side, scope()),
                ScopeObservation {
                    cut: cut.cut.clone(),
                    registry: cut.registry.clone(),
                    population: cut.population.clone(),
                    extractor: version("compiler"),
                    examined: BTreeMap::from([(dep("a"), "a1".into()), (dep("b"), "b1".into())]),
                    live,
                },
            )
        })
        .collect();
        Self {
            basis,
            observations,
            boundary: VerifiedScopeBoundary::Closed {
                contract: version("compiler-admission"),
            },
            fallback: false,
            missing_owner: None,
            change_on_recapture: false,
            reads: Cell::new(0),
        }
    }
}
impl ProcessCaptureAuthority for Authority {
    fn verify_norm_basis(
        &self,
        _: &ProcessBasis,
        _: &whipplescript_store::norm_history::NormReadAnchor,
        _: &EvidenceVersion,
    ) -> Result<(), String> {
        Err("this graph fixture supplies no norm authority".into())
    }
    fn basis(&self, _: &str) -> Result<ProcessBasis, String> {
        let mut basis = self.basis.clone();
        self.reads.set(self.reads.get() + 1);
        if self.change_on_recapture && self.reads.get() > 1 {
            basis.policy = version("changed-policy");
        }
        Ok(basis)
    }
    fn observe(
        &self,
        _: &ProcessBasis,
        side: CutSide,
        scope: &ReferenceScope,
    ) -> Result<ScopeObservation, String> {
        self.observations
            .get(&(side, scope.clone()))
            .cloned()
            .ok_or("scope was not captured".into())
    }
    fn verify_boundary(
        &self,
        _: &ProcessBasis,
        _: CutSide,
        _: &ReferenceScope,
        _: &ScopeObservation,
    ) -> Result<VerifiedScopeBoundary, String> {
        Ok(self.boundary.clone())
    }
    fn owner_validation(
        &self,
        basis: &ProcessBasis,
        _: CutSide,
        scope: &ReferenceScope,
        consumer: &DependencyIdentity,
    ) -> Result<Option<OwnerValidation>, String> {
        Ok(
            (self.fallback && self.missing_owner.as_ref() != Some(consumer)).then(|| {
                OwnerValidation {
                    owner: format!("owner:{}", consumer.identity),
                    candidate_cut: basis.after.cut.clone(),
                    method: scope.class.clone(),
                }
            }),
        )
    }
}

#[test]
fn impact_keeps_deleted_edges_and_transitive_consumers_from_both_cuts() {
    let mut authority = Authority::new();
    authority
        .observations
        .get_mut(&(CutSide::After, scope()))
        .unwrap()
        .live
        .clear();
    let impact = capture_impact(&authority, "candidate").unwrap();
    assert!(impact.blockers.is_empty());
    assert_eq!(
        impact.affected,
        BTreeSet::from([dep("provider"), dep("a"), dep("b")])
    );
    assert_eq!(impact.reasons[&dep("a")], BTreeSet::from([dep("provider")]));
    assert_eq!(impact.reasons[&dep("b")], BTreeSet::from([dep("a")]));
    let wire = serde_json::to_value(&impact).unwrap();
    assert!(wire["basis"]["after"]["scopes"].is_array());
    assert!(wire["coverage"].is_array());
}

#[test]
fn a_registry_scope_or_consumer_omission_never_means_unaffected() {
    let mut authority = Authority::new();
    authority.observations.remove(&(CutSide::After, scope()));
    let impact = capture_impact(&authority, "candidate").unwrap();
    assert!(impact
        .blockers
        .iter()
        .any(|gap| gap.side == CutSide::After && gap.scope == scope()));
    assert!(impact.affected.contains(&dep("b")));
    let mut authority = Authority::new();
    let observation = authority
        .observations
        .get_mut(&(CutSide::After, scope()))
        .unwrap();
    observation.examined.remove(&dep("b"));
    observation.live.retain(|edge| edge.consumer != dep("b"));
    let impact = capture_impact(&authority, "candidate").unwrap();
    assert!(impact
        .blockers
        .iter()
        .any(|gap| gap.reason.contains("omitted a required consumer")));
}

#[test]
fn unknown_coverage_can_widen_only_to_every_installed_exact_owner_validation() {
    let mut authority = Authority::new();
    authority.observations.clear();
    authority.fallback = true;
    let impact = capture_impact(&authority, "candidate").unwrap();
    assert!(impact.blockers.is_empty());
    assert_eq!(impact.validations.len(), 2);
    assert!(matches!(
        impact.coverage[&CutSide::After][&scope()].boundary,
        VerifiedScopeBoundary::Unknown { .. }
    ));
    assert!(impact.coverage[&CutSide::After][&scope()].full_scope_fallback);
    authority.missing_owner = Some(dep("b"));
    let impact = capture_impact(&authority, "candidate").unwrap();
    assert!(!impact.blockers.is_empty());
    assert!(!impact.coverage[&CutSide::After][&scope()].full_scope_fallback);
    assert!(impact.affected.contains(&dep("b")));
}

#[test]
fn an_enforced_envelope_widens_but_a_declared_incomplete_envelope_is_unknown() {
    let mut authority = Authority::new();
    authority.boundary = VerifiedScopeBoundary::Bounded {
        contract: version("installed-ceiling"),
        consumers: BTreeSet::from([dep("a"), dep("b")]),
        providers: BTreeSet::from([dep("provider"), dep("a")]),
    };
    let impact = capture_impact(&authority, "candidate").unwrap();
    assert!(impact.blockers.is_empty());
    assert!(impact.affected.contains(&dep("b")));
    authority.boundary = VerifiedScopeBoundary::Bounded {
        contract: version("installed-ceiling"),
        consumers: BTreeSet::from([dep("a")]),
        providers: BTreeSet::from([dep("provider")]),
    };
    let impact = capture_impact(&authority, "candidate").unwrap();
    assert!(impact
        .blockers
        .iter()
        .any(|gap| gap.reason.contains("envelope omits")));
}

#[test]
fn stale_extraction_and_changed_policy_are_refused_on_their_own_bases() {
    let mut authority = Authority::new();
    authority
        .observations
        .get_mut(&(CutSide::After, scope()))
        .unwrap()
        .population = version("other-roster");
    let impact = capture_impact(&authority, "candidate").unwrap();
    assert!(impact
        .blockers
        .iter()
        .any(|gap| gap.reason.contains("another registry, population or cut")));
    let mut authority = Authority::new();
    authority.change_on_recapture = true;
    assert!(capture_impact(&authority, "candidate")
        .unwrap_err()
        .contains("basis changed during dependency capture"));
}

#[test]
fn another_candidate_or_an_unresolved_consumer_cannot_gain_coverage() {
    let mut authority = Authority::new();
    assert!(capture_impact(&authority, "other")
        .unwrap_err()
        .contains("names another candidate"));
    authority.basis.after.resolutions.remove(&dep("b"));
    assert!(capture_impact(&authority, "candidate")
        .unwrap_err()
        .contains("no exact structural resolution"));
}

#[test]
fn exhaustion_refuses_the_whole_plan_instead_of_returning_partial_impact() {
    let authority = Authority::new();
    let limits = ProcessLimits {
        max_scopes: 1,
        ..ProcessLimits::default()
    };
    assert!(capture_impact_with_limits(&authority, "candidate", limits)
        .unwrap_err()
        .contains("scope or identity budget"));
    let limits = ProcessLimits {
        max_edges: 1,
        ..ProcessLimits::default()
    };
    assert!(capture_impact_with_limits(&authority, "candidate", limits)
        .unwrap_err()
        .contains("extraction budget"));
}

#[test]
fn invalid_extraction_does_not_acquire_coverage_from_its_boundary_label() {
    type Change = fn(&mut ScopeObservation);
    let cases: [(Change, &str); 3] = [
        (
            |observed| observed.extractor.digest.clear(),
            "extractor identity is incomplete",
        ),
        (
            |observed| {
                observed.examined.insert(dep("outside"), "r".into());
            },
            "outside the exact required population",
        ),
        (
            |observed| {
                let mut edge = observed.live.pop_first().unwrap();
                edge.provider_revision = "stale".into();
                observed.live.insert(edge);
            },
            "another provider revision",
        ),
    ];
    for (change, reason) in cases {
        let mut authority = Authority::new();
        change(
            authority
                .observations
                .get_mut(&(CutSide::After, scope()))
                .unwrap(),
        );
        let impact = capture_impact(&authority, "candidate").unwrap();
        assert!(
            impact
                .blockers
                .iter()
                .any(|gap| gap.reason.contains(reason)),
            "{reason}"
        );
    }
}

#[test]
fn an_incomplete_registry_resolution_or_scope_is_not_a_population_proof() {
    let mut authority = Authority::new();
    authority.basis.after.registry.digest.clear();
    assert!(capture_impact(&authority, "candidate")
        .unwrap_err()
        .contains("exact registry or population basis"));
    let mut authority = Authority::new();
    let consumers = authority.basis.after.scopes.remove(&scope()).unwrap();
    let mut unclassified = scope();
    unclassified.class.digest.clear();
    authority.basis.after.scopes.insert(unclassified, consumers);
    assert!(capture_impact(&authority, "candidate")
        .unwrap_err()
        .contains("scope is unclassified"));
    let mut authority = Authority::new();
    let revision = authority
        .basis
        .after
        .resolutions
        .remove(&dep("provider"))
        .unwrap();
    authority.basis.after.resolutions.insert(
        DependencyIdentity {
            authority: "".into(),
            identity: "provider".into(),
        },
        revision,
    );
    assert!(capture_impact(&authority, "candidate")
        .unwrap_err()
        .contains("resolution identity is incomplete"));
}

#[test]
fn oversized_envelopes_are_refused_before_traversal() {
    let mut authority = Authority::new();
    authority.boundary = VerifiedScopeBoundary::Bounded {
        contract: version("ceiling"),
        consumers: BTreeSet::from([dep("a"), dep("b")]),
        providers: (0..8).map(|index| dep(&format!("p{index}"))).collect(),
    };
    let limits = ProcessLimits {
        max_identities: 6,
        ..ProcessLimits::default()
    };
    assert!(capture_impact_with_limits(&authority, "candidate", limits)
        .unwrap_err()
        .contains("envelope budget"));
}
