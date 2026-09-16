//! Resource interpretation pinned by C0, over verified owned artifact captures.
//! This inventories applicability; it does not certify dependencies or admission.
use crate::norm::{NormCharter, NormView};
use crate::norm_artifact::{ArtifactBasis, CapturedArtifact};
use crate::norm_inventory::RequirementInventory;
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceSelector {
    WorkspaceFiles {},
    File { path: String },
    Subtree { root: String },
}
impl ResourceSelector {
    fn matches(&self, path: &str) -> bool {
        match self {
            Self::WorkspaceFiles {} => true,
            Self::File { path: selected } => path == selected,
            Self::Subtree { root } => path
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/')),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDomain {
    pub include: Vec<ResourceSelector>,
}

/// Reject duplicate domain keys before a map can collapse them.
pub(crate) fn decode_domains<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<BTreeMap<String, ResourceDomain>>, D::Error> {
    struct Unique(BTreeMap<String, ResourceDomain>);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            struct Entries;
            impl<'de> serde::de::Visitor<'de> for Entries {
                type Value = Unique;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("unique named resource domains")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Unique, A::Error> {
                    let mut domains = BTreeMap::new();
                    while let Some((name, domain)) = map.next_entry::<String, ResourceDomain>()? {
                        let prior = domains.insert(name, domain);
                        if prior.is_some() {
                            return Err(serde::de::Error::custom(
                                "resource policy repeats a domain name",
                            ));
                        }
                    }
                    Ok(Unique(domains))
                }
            }
            decoder.deserialize_map(Entries)
        }
    }
    Ok(Option::<Unique>::deserialize(decoder)?.map(|unique| unique.0))
}

pub(crate) fn validate_resource_domains(charter: &NormCharter) -> StoreResult<()> {
    for (name, domain) in charter.resource_domains.iter().flatten() {
        if name.trim().is_empty() || name.trim() != name {
            return Err(StoreError::Conflict(
                "resource domain names must be nonempty and trimmed".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for selector in &domain.include {
            let unique = seen.insert(selector);
            let canonical = match selector {
                ResourceSelector::WorkspaceFiles {} => true,
                ResourceSelector::File { path } => crate::norm_artifact::canonical_path(path),
                ResourceSelector::Subtree { root } => crate::norm_artifact::canonical_path(root),
            };
            if !unique || !canonical {
                return Err(StoreError::Conflict(
                    "resource selectors must be unique canonical paths".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Bounds selector comparisons and produced associations, in addition to the
/// artifact capture's own bounds. It is not a wall-clock or exact heap bound.
#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub max_work: usize,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_work: 1_000_000,
        }
    }
}
struct Budget(usize);
impl Budget {
    fn step(&mut self) -> StoreResult<()> {
        if self.0 == 0 {
            return Err(StoreError::Conflict(
                "resource inventory exceeds its work budget".into(),
            ));
        }
        self.0 -= 1;
        Ok(())
    }
    fn matches(&mut self, domain: &ResourceDomain, path: &str) -> StoreResult<bool> {
        for selector in &domain.include {
            self.step()?;
            if selector.matches(path) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceGapKind {
    MissingPolicy {},
    UninterpretedRequirement {},
    UnknownDomain { domain: String },
    InvalidSubject { subject: String },
    SubjectOutsideDomain {},
    MissingSubject {},
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceGap {
    pub requirement: Option<String>,
    pub reason: ResourceGapKind,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCoverage {
    pub domains: BTreeSet<String>,
    pub requirements: BTreeSet<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementResources {
    pub domain: String,
    pub subject: String,
    pub subject_present: bool,
    pub resources: BTreeSet<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceInventory {
    pub artifact: ArtifactBasis,
    pub inventory: RequirementInventory,
    /// None remains unknown; Some(empty) is an explicitly empty managed domain.
    pub domains: Option<BTreeMap<String, ResourceDomain>>,
    pub resources: BTreeMap<String, ResourceCoverage>,
    pub bindings: BTreeMap<String, RequirementResources>,
    pub unmanaged: BTreeSet<String>,
    pub uncovered: BTreeSet<String>,
    pub unresolved: BTreeSet<String>,
    pub gaps: Vec<ResourceGap>,
    /// All active records interpreted and bound, not all resources covered,
    /// evidence adequate, runtime reads closed, or admission permitted.
    pub binding_complete: bool,
}

fn inventory(
    view: &NormView,
    artifact: &CapturedArtifact,
    budget: &mut Budget,
) -> StoreResult<ResourceInventory> {
    budget.step()?;
    validate_resource_domains(&view.charter)?;
    let mut result = ResourceInventory {
        artifact: artifact.basis().clone(),
        inventory: view.requirement_inventory()?,
        domains: view.charter.resource_domains.clone(),
        resources: BTreeMap::new(),
        bindings: BTreeMap::new(),
        unmanaged: BTreeSet::new(),
        uncovered: BTreeSet::new(),
        unresolved: BTreeSet::new(),
        gaps: Vec::new(),
        binding_complete: false,
    };
    if result.domains.is_none() {
        result.gaps.push(ResourceGap {
            requirement: None,
            reason: ResourceGapKind::MissingPolicy {},
        });
    }
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in artifact.files().keys() {
        budget.step()?;
        let mut coverage = ResourceCoverage::default();
        for (name, domain) in result.domains.iter().flatten() {
            budget.step()?;
            if budget.matches(domain, path)? {
                coverage.domains.insert(name.clone());
                members
                    .entry(name.clone())
                    .or_default()
                    .insert(path.clone());
            }
        }
        result.resources.insert(path.clone(), coverage);
    }
    for (id, requirement) in &result.inventory.requirements {
        budget.step()?;
        let gap = |reason| ResourceGap {
            requirement: Some(id.clone()),
            reason,
        };
        let Some(declaration) = &requirement.declaration else {
            result
                .gaps
                .push(gap(ResourceGapKind::UninterpretedRequirement {}));
            continue;
        };
        let Some(domains) = &result.domains else {
            continue;
        };
        let Some(domain) = domains.get(&declaration.domain) else {
            result.gaps.push(gap(ResourceGapKind::UnknownDomain {
                domain: declaration.domain.clone(),
            }));
            continue;
        };
        if !crate::norm_artifact::canonical_path(&declaration.subject) {
            result.gaps.push(gap(ResourceGapKind::InvalidSubject {
                subject: declaration.subject.clone(),
            }));
            continue;
        }
        if !budget.matches(domain, &declaration.subject)? {
            result
                .gaps
                .push(gap(ResourceGapKind::SubjectOutsideDomain {}));
            continue;
        }
        let subject_present = artifact.files().contains_key(&declaration.subject);
        if !subject_present {
            result.gaps.push(gap(ResourceGapKind::MissingSubject {}));
        }
        let mut resources = BTreeSet::new();
        for path in members.get(&declaration.domain).into_iter().flatten() {
            budget.step()?;
            resources.insert(path.clone());
            result
                .resources
                .get_mut(path)
                .expect("captured member")
                .requirements
                .insert(id.clone());
        }
        result.bindings.insert(
            id.clone(),
            RequirementResources {
                domain: declaration.domain.clone(),
                subject: declaration.subject.clone(),
                subject_present,
                resources,
            },
        );
    }
    let uncertain = !result.inventory.classification_complete
        || result
            .gaps
            .iter()
            .any(|gap| gap.reason != ResourceGapKind::MissingSubject {});
    // An unknown policy cannot establish which files are outside its domain.
    if result.domains.is_some() {
        for (path, coverage) in &result.resources {
            if coverage.domains.is_empty() {
                result.unmanaged.insert(path.clone());
            } else if coverage.requirements.is_empty() {
                if uncertain {
                    result.unresolved.insert(path.clone());
                } else {
                    result.uncovered.insert(path.clone());
                }
            }
        }
    } else {
        result.unresolved.extend(result.resources.keys().cloned());
    }
    result.binding_complete = result.inventory.classification_complete && result.gaps.is_empty();
    Ok(result)
}

impl NormView {
    pub fn resource_inventory(
        &self,
        artifact: &CapturedArtifact,
        limits: ResourceLimits,
    ) -> StoreResult<ResourceInventory> {
        inventory(self, artifact, &mut Budget(limits.max_work))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceChange {
    Created,
    Modified,
    Deleted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceInventoryPair {
    pub before: ResourceInventory,
    pub after: ResourceInventory,
    /// Union: retirement/deletion cannot erase a duty from the comparison.
    pub requirements: BTreeSet<String>,
    pub changes: BTreeMap<String, ResourceChange>,
}
/// The norm history must extend the prior captured view. The two artifacts are
/// explicit comparison inputs; this does not assert VCS ancestry or a gate.
pub fn compare_resources(
    before_view: &NormView,
    before: &CapturedArtifact,
    after_view: &NormView,
    after: &CapturedArtifact,
    limits: ResourceLimits,
) -> StoreResult<ResourceInventoryPair> {
    let known: BTreeSet<_> = after_view.event_order().iter().collect();
    if before_view.ledger != after_view.ledger
        || before_view
            .event_order()
            .iter()
            .any(|id| !known.contains(id))
    {
        return Err(StoreError::Conflict(
            "resource comparison needs an extension of the same norm history".into(),
        ));
    }
    let mut budget = Budget(limits.max_work);
    let before_inventory = inventory(before_view, before, &mut budget)?;
    let after_inventory = inventory(after_view, after, &mut budget)?;
    let requirements = before_inventory
        .inventory
        .requirements
        .keys()
        .chain(after_inventory.inventory.requirements.keys())
        .cloned()
        .collect();
    let mut changes = BTreeMap::new();
    for path in before.files().keys().chain(after.files().keys()) {
        budget.step()?;
        let change = match (before.files().get(path), after.files().get(path)) {
            (None, Some(_)) => Some(ResourceChange::Created),
            (Some(_), None) => Some(ResourceChange::Deleted),
            (Some(left), Some(right)) if left != right => Some(ResourceChange::Modified),
            _ => None,
        };
        if let Some(change) = change {
            changes.insert(path.clone(), change);
        }
    }
    Ok(ResourceInventoryPair {
        before: before_inventory,
        after: after_inventory,
        requirements,
        changes,
    })
}
