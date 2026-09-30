//! Versioned source-process impact derivation (DR-0131, DR-0152).
//!
//! The embedding owns authenticated registry, population, extraction and
//! enforced-boundary reads. Request data never supplies those facts. This
//! module derives the conservative consumer/work set; it owns no Home roster,
//! dependency extractor, work store, execution scheduler or publication door.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use whipplescript_core::norm_evidence::EvidenceVersion;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct DependencyIdentity {
    pub authority: String,
    pub identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReferenceScope {
    pub class: EvidenceVersion,
    pub consumer_scope: String,
}
impl Ord for ReferenceScope {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            &self.class.name,
            &self.class.version,
            &self.class.digest,
            &self.consumer_scope,
        )
            .cmp(&(
                &other.class.name,
                &other.class.version,
                &other.class.digest,
                &other.consumer_scope,
            ))
    }
}
impl PartialOrd for ReferenceScope {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CutSide {
    Before,
    After,
}

/// Required scopes and consumers come from the admitted registry and closed
/// population, independently of whichever extraction happened to succeed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StructuralCut {
    pub cut: String,
    pub registry: EvidenceVersion,
    pub population: EvidenceVersion,
    #[serde(serialize_with = "entries")]
    pub resolutions: BTreeMap<DependencyIdentity, String>,
    #[serde(serialize_with = "entries")]
    pub scopes: BTreeMap<ReferenceScope, BTreeSet<DependencyIdentity>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessBasis {
    pub home: String,
    pub candidate_witness_digest: String,
    pub native_base_cut: Option<String>,
    pub native_candidate_cut: String,
    pub seal: EvidenceVersion,
    pub policy: EvidenceVersion,
    pub before: StructuralCut,
    pub after: StructuralCut,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct LiveDependency {
    pub consumer: DependencyIdentity,
    pub consumer_revision: String,
    pub provider: DependencyIdentity,
    pub provider_revision: String,
}

/// Returned by the owning boundary after it verifies exact extraction and its
/// own undeclared-edge refusal/envelope contract. This is not a request flag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum VerifiedScopeBoundary {
    Closed {
        contract: EvidenceVersion,
    },
    Bounded {
        contract: EvidenceVersion,
        consumers: BTreeSet<DependencyIdentity>,
        providers: BTreeSet<DependencyIdentity>,
    },
    Unknown {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScopeObservation {
    pub cut: String,
    pub registry: EvidenceVersion,
    pub population: EvidenceVersion,
    pub extractor: EvidenceVersion,
    #[serde(serialize_with = "entries")]
    pub examined: BTreeMap<DependencyIdentity, String>,
    /// Only references whose admitted class means a live update dependency.
    /// Owning extractors retain historical, provenance and authority meanings
    /// separately; this process does not reinterpret them as live edges.
    pub live: BTreeSet<LiveDependency>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OwnerValidation {
    pub owner: String,
    pub candidate_cut: String,
    pub method: EvidenceVersion,
}

/// An admitted mapping from an owning full-scope validator to a norm duty.
/// The contract must establish that this requirement/method exercises the
/// complete named consumer at the candidate structural cut, including its
/// source/resolution and world premises. A matching record name alone cannot
/// establish that correspondence. It supplies no execution result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NormValidationBinding {
    pub contract: EvidenceVersion,
    pub ledger: String,
    pub record: String,
    pub requirement: EvidenceVersion,
}
impl Ord for OwnerValidation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            &self.owner,
            &self.candidate_cut,
            &self.method.name,
            &self.method.version,
            &self.method.digest,
        )
            .cmp(&(
                &other.owner,
                &other.candidate_cut,
                &other.method.name,
                &other.method.version,
                &other.method.digest,
            ))
    }
}
impl PartialOrd for OwnerValidation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An installed host binding, not a wire decoder or a caller's observations.
/// Basis closes the admitted reference registry and operation population at the
/// requested seal, or returns an error naming the missing authority. Extraction
/// is read from its owning boundary at that exact structural cut. Verification
/// must establish the admitting boundary's actual installed contract, not just
/// compare an observation's declaration with itself or check its signature.
pub trait ProcessCaptureAuthority {
    fn basis(&self, candidate_witness_digest: &str) -> Result<ProcessBasis, String>;
    /// Verify that this exact derivation implementation is installed under the
    /// admitted process policy at this Home basis. A population seal, package
    /// signature or successful norm judgment supplies no methodology grant.
    /// The owning reader must establish standing and installation independently
    /// of the implementation identity supplied for comparison.
    fn verify_process_basis(
        &self,
        basis: &ProcessBasis,
        process: &EvidenceVersion,
    ) -> Result<(), String>;
    fn observe(
        &self,
        basis: &ProcessBasis,
        side: CutSide,
        scope: &ReferenceScope,
    ) -> Result<ScopeObservation, String>;
    fn verify_boundary(
        &self,
        basis: &ProcessBasis,
        side: CutSide,
        scope: &ReferenceScope,
        observation: &ScopeObservation,
    ) -> Result<VerifiedScopeBoundary, String>;
    /// The Home binds the independently verified norm read and installed
    /// evidence policy to the same admitted process/structural basis. A
    /// signature on an unrelated seal is insufficient.
    fn verify_norm_basis(
        &self,
        basis: &ProcessBasis,
        anchor: &whipplescript_store::norm_history::NormReadAnchor,
        policy: &EvidenceVersion,
    ) -> Result<(), String>;
    /// An independently installed exact-candidate validator and owning route.
    /// None blocks an affected consumer and prevents unknown graph coverage
    /// from using a full-scope fallback. This is required work, not a passing
    /// execution observation.
    fn owner_validation(
        &self,
        basis: &ProcessBasis,
        side: CutSide,
        scope: &ReferenceScope,
        consumer: &DependencyIdentity,
    ) -> Result<Option<OwnerValidation>, String>;

    /// Read the independently installed correspondence contract under the
    /// admitted process policy. The norm reader independently authenticates
    /// the exact requirement and selects its evidence at the candidate.
    /// Returning None keeps the work owed; adapters need not pretend that an
    /// external owning validator is represented in the local norm ledger.
    fn validation_requirement(
        &self,
        _basis: &ProcessBasis,
        _consumer: &DependencyIdentity,
        _validation: &OwnerValidation,
    ) -> Result<Option<NormValidationBinding>, String> {
        Ok(None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct CoverageGap {
    pub side: CutSide,
    pub scope: ReferenceScope,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScopeCoverage {
    pub observation: Option<ScopeObservation>,
    pub boundary: VerifiedScopeBoundary,
    pub full_scope_fallback: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessImpact {
    pub basis: ProcessBasis,
    /// Always retain unknown graph coverage, even when exact full-scope
    /// validation supplies a conservative way to discharge its uncertainty.
    #[serde(serialize_with = "coverage_entries")]
    pub coverage: BTreeMap<CutSide, BTreeMap<ReferenceScope, ScopeCoverage>>,
    pub changed: BTreeSet<DependencyIdentity>,
    pub affected: BTreeSet<DependencyIdentity>,
    #[serde(serialize_with = "entries")]
    pub reasons: BTreeMap<DependencyIdentity, BTreeSet<DependencyIdentity>>,
    #[serde(serialize_with = "entries")]
    pub validations: BTreeMap<DependencyIdentity, BTreeSet<OwnerValidation>>,
    pub blockers: BTreeSet<CoverageGap>,
}

fn entries<K: Serialize, V: Serialize, S: serde::Serializer>(
    map: &BTreeMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Entry<'a, K, V> {
        key: &'a K,
        value: &'a V,
    }
    map.iter()
        .map(|(key, value)| Entry { key, value })
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn coverage_entries<S: serde::Serializer>(
    map: &BTreeMap<CutSide, BTreeMap<ReferenceScope, ScopeCoverage>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Side<'a> {
        side: CutSide,
        #[serde(serialize_with = "entries")]
        scopes: &'a BTreeMap<ReferenceScope, ScopeCoverage>,
    }
    map.iter()
        .map(|(side, scopes)| Side {
            side: *side,
            scopes,
        })
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn complete_identity(identity: &EvidenceVersion) -> bool {
    [&identity.name, &identity.version, &identity.digest]
        .iter()
        .all(|part| !part.trim().is_empty())
}

fn coherent_observation(
    cut: &StructuralCut,
    scope: &ReferenceScope,
    observation: &ScopeObservation,
) -> Result<(), String> {
    if observation.cut != cut.cut
        || observation.registry != cut.registry
        || observation.population != cut.population
    {
        return Err("extraction belongs to another registry, population or cut".into());
    }
    if !complete_identity(&observation.extractor) {
        return Err("extractor identity is incomplete".into());
    }
    let population = &cut.scopes[scope];
    for (consumer, revision) in &observation.examined {
        if !population.contains(consumer) || cut.resolutions.get(consumer) != Some(revision) {
            return Err("examined consumer is outside the exact required population".into());
        }
    }
    for edge in &observation.live {
        if observation.examined.get(&edge.consumer) != Some(&edge.consumer_revision)
            || cut.resolutions.get(&edge.provider) != Some(&edge.provider_revision)
        {
            return Err(
                "dependency edge has an unexamined consumer or another provider revision".into(),
            );
        }
    }
    Ok(())
}

fn validate_basis(basis: &ProcessBasis, requested: &str) -> Result<(), String> {
    if basis.candidate_witness_digest != requested
        || basis.home.trim().is_empty()
        || basis.native_candidate_cut.trim().is_empty()
        || !complete_identity(&basis.seal)
        || !complete_identity(&basis.policy)
    {
        return Err("Home process basis is incomplete or names another candidate".into());
    }
    for cut in [&basis.before, &basis.after] {
        if cut.cut.trim().is_empty()
            || !complete_identity(&cut.registry)
            || !complete_identity(&cut.population)
        {
            return Err("structural cut lacks its exact registry or population basis".into());
        }
        for (scope, consumers) in &cut.scopes {
            if !complete_identity(&scope.class) || scope.consumer_scope.trim().is_empty() {
                return Err("required reference scope is unclassified".into());
            }
            if consumers
                .iter()
                .any(|consumer| !cut.resolutions.contains_key(consumer))
            {
                return Err("required consumer has no exact structural resolution".into());
            }
        }
        if cut.resolutions.iter().any(|(identity, revision)| {
            identity.authority.trim().is_empty()
                || identity.identity.trim().is_empty()
                || revision.trim().is_empty()
        }) {
            return Err("structural resolution identity is incomplete".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct ProcessLimits {
    pub max_scopes: usize,
    pub max_identities: usize,
    pub max_edges: usize,
}
impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            max_scopes: 1_000,
            max_identities: 100_000,
            max_edges: 1_000_000,
        }
    }
}

/// Conservative impact over the union of exact before/after live edges and
/// enforced envelopes. Roots come from the structural vector's changes; the
/// requester cannot narrow them. Missing scopes are visited from the admitted
/// registry, not from a successful extraction list. Bounded/unknown scopes can
/// widen work but cannot make selected source units dependency closed.
pub fn capture_impact(
    authority: &dyn ProcessCaptureAuthority,
    requested: &str,
) -> Result<ProcessImpact, String> {
    capture_impact_with_limits(authority, requested, ProcessLimits::default())
}

pub fn capture_impact_with_limits(
    authority: &dyn ProcessCaptureAuthority,
    requested: &str,
    limits: ProcessLimits,
) -> Result<ProcessImpact, String> {
    let basis = authority.basis(requested)?;
    if limits.max_scopes == 0
        || limits.max_identities == 0
        || limits.max_edges == 0
        || basis
            .before
            .scopes
            .len()
            .saturating_add(basis.after.scopes.len())
            > limits.max_scopes
        || basis
            .before
            .resolutions
            .len()
            .saturating_add(basis.after.resolutions.len())
            > limits.max_identities
        || basis
            .before
            .scopes
            .values()
            .chain(basis.after.scopes.values())
            .map(BTreeSet::len)
            .fold(0usize, usize::saturating_add)
            > limits.max_identities
    {
        return Err("source process capture exceeds its scope or identity budget".into());
    }
    validate_basis(&basis, requested)?;
    let changed: BTreeSet<_> = basis
        .before
        .resolutions
        .keys()
        .chain(basis.after.resolutions.keys())
        .filter(|key| basis.before.resolutions.get(*key) != basis.after.resolutions.get(*key))
        .cloned()
        .collect();
    let mut result = ProcessImpact {
        basis: basis.clone(),
        coverage: BTreeMap::new(),
        changed: changed.clone(),
        affected: changed,
        reasons: BTreeMap::new(),
        validations: BTreeMap::new(),
        blockers: BTreeSet::new(),
    };
    let mut live = BTreeSet::new();
    let mut examined_edges = 0usize;
    for (side, cut) in [
        (CutSide::Before, &basis.before),
        (CutSide::After, &basis.after),
    ] {
        for (scope, population) in &cut.scopes {
            let observation = authority.observe(&basis, side, scope);
            if let Ok(observed) = &observation {
                examined_edges = examined_edges.saturating_add(observed.live.len());
                if observed.examined.len() > limits.max_identities
                    || examined_edges > limits.max_edges
                {
                    return Err("source process capture exceeds its extraction budget".into());
                }
            }
            let observation = observation.and_then(|observed| {
                coherent_observation(cut, scope, &observed)?;
                Ok(observed)
            });
            let mut boundary = match &observation {
                Ok(observed) => authority
                    .verify_boundary(&basis, side, scope, observed)
                    .unwrap_or_else(|reason| VerifiedScopeBoundary::Unknown { reason }),
                Err(reason) => VerifiedScopeBoundary::Unknown {
                    reason: reason.clone(),
                },
            };
            match &boundary {
                VerifiedScopeBoundary::Closed { contract } => {
                    if !complete_identity(contract)
                        || observation.as_ref().is_ok_and(|observed| {
                            observed.examined.keys().cloned().collect::<BTreeSet<_>>()
                                != *population
                        })
                    {
                        boundary = VerifiedScopeBoundary::Unknown { reason: "closed extraction omitted a required consumer or its boundary contract".into() };
                    }
                }
                VerifiedScopeBoundary::Bounded {
                    contract,
                    consumers,
                    providers,
                } => {
                    if consumers.len().saturating_add(providers.len()) > limits.max_identities {
                        return Err("source process capture exceeds its envelope budget".into());
                    }
                    if !complete_identity(contract)
                        || !population.is_subset(consumers)
                        || consumers
                            .iter()
                            .chain(providers)
                            .any(|identity| !cut.resolutions.contains_key(identity))
                        || observation.as_ref().is_ok_and(|observed| {
                            observed.live.iter().any(|edge| {
                                !consumers.contains(&edge.consumer)
                                    || !providers.contains(&edge.provider)
                            })
                        })
                    {
                        boundary = VerifiedScopeBoundary::Unknown { reason: "enforced envelope omits the required population or an exact resolution".into() };
                    }
                }
                VerifiedScopeBoundary::Unknown { .. } => {}
            }
            if let Ok(observed) = &observation {
                live.extend(observed.live.iter().cloned());
            }
            let mut fallback = false;
            let conservatively_affected = match &boundary {
                VerifiedScopeBoundary::Closed { .. } => BTreeSet::new(),
                VerifiedScopeBoundary::Bounded { consumers, .. } => consumers.clone(),
                VerifiedScopeBoundary::Unknown { reason } => {
                    fallback = true;
                    // Validate every required owner, even when no edge was
                    // observed. A missing owner/method cannot shrink this set.
                    for consumer in population {
                        match authority.owner_validation(&basis, side, scope, consumer) {
                            Ok(Some(validation))
                                if !validation.owner.trim().is_empty()
                                    && validation.candidate_cut == basis.after.cut
                                    && complete_identity(&validation.method) =>
                            {
                                result
                                    .validations
                                    .entry(consumer.clone())
                                    .or_default()
                                    .insert(validation);
                            }
                            _ => {
                                fallback = false;
                            }
                        }
                    }
                    if !fallback {
                        result.blockers.insert(CoverageGap {
                            side,
                            scope: scope.clone(),
                            reason: reason.clone(),
                        });
                    }
                    population.clone()
                }
            };
            result.affected.extend(conservatively_affected);
            result.coverage.entry(side).or_default().insert(
                scope.clone(),
                ScopeCoverage {
                    observation: observation.ok(),
                    boundary,
                    full_scope_fallback: fallback,
                },
            );
        }
    }
    let mut pending: Vec<_> = result.affected.iter().cloned().collect();
    let mut expanded = BTreeSet::new();
    let mut consumers_of = BTreeMap::<_, BTreeSet<_>>::new();
    for edge in live {
        consumers_of
            .entry(edge.provider)
            .or_default()
            .insert(edge.consumer);
    }
    while let Some(provider) = pending.pop() {
        if !expanded.insert(provider.clone()) {
            continue;
        }
        for consumer in consumers_of.get(&provider).into_iter().flatten() {
            result
                .reasons
                .entry(consumer.clone())
                .or_default()
                .insert(provider.clone());
            if result.affected.insert(consumer.clone()) {
                pending.push(consumer.clone());
            }
        }
    }
    // Closed graph coverage identifies affected consumers; it does not check
    // them. Bounded coverage routes every consumer in its enforced envelope.
    // Unknown scopes already requested every required owning validator above.
    for (side, cut) in [
        (CutSide::Before, &basis.before),
        (CutSide::After, &basis.after),
    ] {
        for (scope, population) in &cut.scopes {
            let members = match &result.coverage[&side][scope].boundary {
                VerifiedScopeBoundary::Closed { .. } => population,
                VerifiedScopeBoundary::Bounded { consumers, .. } => consumers,
                VerifiedScopeBoundary::Unknown { .. } => continue,
            };
            for consumer in result.affected.intersection(members) {
                match authority.owner_validation(&basis, side, scope, consumer) {
                    Ok(Some(validation))
                        if !validation.owner.trim().is_empty()
                            && validation.candidate_cut == basis.after.cut
                            && complete_identity(&validation.method) =>
                    {
                        result
                            .validations
                            .entry(consumer.clone())
                            .or_default()
                            .insert(validation);
                    }
                    _ => {
                        result.blockers.insert(CoverageGap {
                        side, scope: scope.clone(), reason: format!("affected consumer {}/{} has no installed exact-candidate owning validator", consumer.authority, consumer.identity)
                    });
                    }
                }
            }
        }
    }
    // The owning reader chooses the same sealed cut after ordinary later
    // admissions. A changed relevant basis, rather than a global live journal
    // revision, invalidates this capture.
    if authority.basis(requested)? != basis {
        return Err("source process basis changed during dependency capture".into());
    }
    Ok(result)
}

#[cfg(test)]
#[path = "source_process_tests.rs"]
mod tests;
