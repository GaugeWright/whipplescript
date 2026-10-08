//! Source-process composition (DR-0152), not another norm or ref authority.
//!
//! Read-only native derivation uses the owning VCS and authenticated norm
//! readers. Local reference observations never establish a Home population.
//! This result deliberately has no certificate conversion: coverage authority,
//! isolated execution and the final publication fence must be bound separately.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_core::norm_selection::EvidenceSelection;
use whipplescript_store::branches::flowing_abandonment::FlowingAbandonments;
use whipplescript_store::branches::flowing_admission::FlowingAdmissions;
use whipplescript_store::branches::flowing_admission::FlowingCandidateWitness;
use whipplescript_store::branches::flowing_fence::FlowingFence;
use whipplescript_store::branches::flowing_fence::FlowingFenceState;
use whipplescript_store::branches::flowing_holders::FlowingUnitHolder;
use whipplescript_store::branches::flowing_sources::FlowingSources;
use whipplescript_store::branches::Branches;
use whipplescript_store::content::ContentBlobs;
use whipplescript_store::norm_artifact::ArtifactLimits;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::norm_reference_inventory::{
    inventory_at, observed_acts_at, observed_edges_at, NormReferenceMeaning,
};
use whipplescript_store::norm_resources::RequirementResources;
use whipplescript_store::source_review_types::{NativeReviewReadError, NativeReviewReader};
#[cfg(feature = "native")]
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::vcs::WorkspaceVcs;
use whipplescript_store::RuntimeStore;

use crate::norm_admission::{AdmissionHost, AdmissionLedger};
use crate::norm_impact::{ImpactBasis, ImpactWork};
use crate::norm_planning::{ImpactQuery, Planned};
use crate::source_process::{
    DependencyIdentity, NormValidationBinding, ProcessCaptureAuthority, ProcessImpact,
    ReferenceScope,
};

#[derive(Clone, Debug, Serialize)]
pub struct SourceAdmissionSubject {
    pub witness_digest: String,
    pub witness: FlowingCandidateWitness,
    pub source_fence: FlowingFenceState,
    pub lineage_fences: Vec<FlowingFenceState>,
    pub unit_holders: Vec<FlowingUnitHolder>,
}

/// Located gaps are part of the judgment, including gaps outside the locally
/// observed ledger. An empty local reference set cannot remove them.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct LocatedBlocker {
    pub scope: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceObligation {
    pub record: String,
    pub requirement: Option<EvidenceVersion>,
    pub bases: BTreeSet<ImpactBasis>,
    /// Prior obligations are interpreted at the candidate under prior policy.
    pub applicability: BTreeMap<ImpactBasis, RequirementResources>,
    pub work: ImpactWork,
    pub support: Option<EvidenceSelection>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReferenceClassObservation {
    pub contract: EvidenceVersion,
    pub vocabulary: String,
    pub version: String,
    pub field: String,
    pub meaning: Option<NormReferenceMeaning>,
}

/// An owning full-scope check required by dependency impact. Finding its
/// installed method does not establish that it ran or that its result passed.
#[derive(Clone, Debug, Serialize)]
pub struct DependencyValidationWork {
    pub consumer: DependencyIdentity,
    pub owner: String,
    pub method: EvidenceVersion,
    pub structural_cut: String,
    pub binding: Option<NormValidationBinding>,
}

/// References the independently derived local obligation rather than accepting
/// a second serialized evidence judgment from the owning route. All selected
/// observations and adequacy diagnostics remain in that obligation's support.
#[derive(Clone, Debug, Serialize)]
pub struct DependencyValidationJudgment {
    pub obligation: Option<String>,
    pub work: ImpactWork,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReferenceEdgeObservation {
    pub consumer: String,
    pub consumer_revision: String,
    pub vocabulary: String,
    pub vocabulary_version: String,
    pub field: String,
    pub occurrence: String,
    pub provider: String,
    pub resolved_revision: Option<String>,
    pub meaning: Option<NormReferenceMeaning>,
}

/// A truthful local observation. It is not a serializable authority token or
/// an input that can be replayed to supply Home coverage.
#[derive(Clone, Debug, Serialize)]
pub struct LocalReferenceObservation {
    pub ledger: String,
    pub authority_head: String,
    pub frontier: Vec<String>,
    pub charter_digest: String,
    pub charter_events: Vec<String>,
    pub required_classes: Vec<ReferenceClassObservation>,
    pub observed_acts: BTreeSet<String>,
    pub edges: Vec<ReferenceEdgeObservation>,
    pub historical_population_unknown: bool,
}

/// Source verification is an observation derived by the owning VCS reader.
/// The judgment binds this original revision identity to its exact subject;
/// serialization cannot supply a proof or authorize admission.
#[derive(Clone, Debug, Serialize)]
pub struct SourceCandidateVerification {
    pub review_revision: EvidenceVersion,
}

/// Trusted embedding inputs. A process package cannot install its own review
/// record or substitute Home coverage for source verification.
#[derive(Clone, Copy, Default)]
pub struct SourceAdmissionCapture<'a> {
    pub home: Option<&'a dyn ProcessCaptureAuthority>,
    pub review: Option<&'a dyn NativeReviewReader>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceAdmissionJudgment {
    pub protocol: &'static str,
    pub process: EvidenceVersion,
    pub subject: SourceAdmissionSubject,
    pub source_verification: Option<SourceCandidateVerification>,
    pub interpretation: EvidenceVersion,
    /// The complete typed norm result, including its read anchors, requirement
    /// inventories, selected evidence, resource and discovery gaps.
    pub norm: serde_json::Value,
    pub obligations: BTreeMap<String, SourceObligation>,
    pub references: LocalReferenceObservation,
    pub dependencies: Option<ProcessImpact>,
    pub dependency_work: BTreeMap<String, DependencyValidationWork>,
    pub dependency_judgments: BTreeMap<String, DependencyValidationJudgment>,
    pub blockers: BTreeSet<LocatedBlocker>,
}

/// No deserializer or public constructor. Only derivation from owning readers
/// creates this immutable result. A plan identity is not admission authority.
#[derive(Clone, Debug)]
pub struct SourceAdmissionPlan {
    identity: String,
    judgment: SourceAdmissionJudgment,
}

impl SourceAdmissionPlan {
    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn judgment(&self) -> &SourceAdmissionJudgment {
        &self.judgment
    }
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"identity": self.identity, "judgment": self.judgment})
    }
}

fn identity(value: &impl Serialize) -> Result<String, String> {
    // Value canonicalizes object key order; vectors must be canonically ordered
    // by their owning derivation. Operational queue order is never an input.
    let canonical = serde_json::to_value(value).map_err(|error| format!("{error:?}"))?;
    let bytes = serde_json::to_vec(&canonical).map_err(|error| format!("{error:?}"))?;
    Ok(format!("sha256:{}", crate::exec_http::sha256_hex(&bytes)))
}

fn process_identity() -> Result<EvidenceVersion, String> {
    Ok(EvidenceVersion {
        name: "whipplescript.source-admission.full-norm".into(),
        version: "1".into(),
        digest: identity(&(
            crate::exec_http::sha256_hex(include_bytes!("source_admission.rs")),
            crate::exec_http::sha256_hex(include_bytes!("source_process.rs")),
        ))?,
    })
}

fn obligations(
    witness_digest: &str,
    planned: &Planned,
) -> Result<BTreeMap<String, SourceObligation>, String> {
    let mut result = BTreeMap::new();
    for (record, impacts) in &planned.plan.requirements {
        for impact in impacts {
            let mut applicability = BTreeMap::new();
            for basis in &impact.bases {
                let inventory = match basis {
                    ImpactBasis::Before => &planned.plan.prior_at_candidate,
                    ImpactBasis::After => &planned.plan.resources.after,
                };
                if let Some(binding) = inventory.bindings.get(record) {
                    applicability.insert(*basis, binding.clone());
                }
            }
            let id = identity(&(
                "source-obligation-v1",
                witness_digest,
                record,
                &impact.requirement,
                &impact.bases,
                &applicability,
            ))?;
            let obligation = SourceObligation {
                record: record.clone(),
                requirement: impact.requirement.clone(),
                bases: impact.bases.clone(),
                applicability,
                work: impact.work.clone(),
                support: impact.selection.clone(),
            };
            // Equal interpreted requirements share one norm selection;
            // distinct versions or uninterpreted bases remain distinct here.
            result.insert(id, obligation);
        }
    }
    Ok(result)
}

fn validation_judgment(
    work: &DependencyValidationWork,
    ledger: &str,
    obligations: &BTreeMap<String, SourceObligation>,
) -> DependencyValidationJudgment {
    let gap = |reason: &str| DependencyValidationJudgment {
        obligation: None,
        work: ImpactWork::ObservationGap,
        reason: Some(reason.into()),
    };
    let Some(binding) = &work.binding else {
        return gap("owning validation is required; no independently verified execution evidence or admitted norm correspondence was captured");
    };
    if binding.ledger != ledger
        || binding.record.trim().is_empty()
        || [
            &binding.contract.name,
            &binding.contract.version,
            &binding.contract.digest,
        ]
        .iter()
        .any(|part| part.trim().is_empty())
    {
        return gap("owning validation correspondence has no exact local ledger or contract");
    }
    let matches: Vec<_> = obligations
        .iter()
        .filter(|(_, obligation)| {
            obligation.record == binding.record
                && obligation.requirement.as_ref() == Some(&binding.requirement)
        })
        .collect();
    if matches.len() != 1 {
        return gap("owning validation correspondence has no unique exact candidate obligation");
    }
    let (id, obligation) = matches[0];
    let method_matches = match &obligation.work {
        ImpactWork::Supported => obligation.support.as_ref().is_some_and(|selection| {
            selection.positive.iter().any(|event| {
                selection
                    .judgments
                    .get(event)
                    .is_some_and(|judgment| judgment.subject.method == work.method)
            })
        }),
        ImpactWork::Check { method } => method == &work.method,
        _ => true,
    };
    DependencyValidationJudgment {
        obligation: Some(id.clone()),
        work: if method_matches {
            obligation.work.clone()
        } else {
            ImpactWork::ObservationGap
        },
        reason: (!method_matches)
            .then(|| "selected norm method does not establish this exact owning validation".into()),
    }
}

/// Derive the candidate's full local norm obligations. No requirement is
/// filtered by a partial reverse-dependency query. The Home's authoritative
/// population/cut is still owed and remains an explicit blocking scope.
///
/// The caller selects only a retained witness and attempt; policy, methods,
/// artifacts and evidence come from the embedding's owning readers. This
/// function creates no issue, claim, execution, certificate or publication.
#[cfg(feature = "native")]
pub fn plan_native<L: AdmissionLedger, S: RuntimeStore>(
    vcs: &NativeWorkspaceVcs,
    ledger: &L,
    host: AdmissionHost<'_, S>,
    witness_digest: &str,
    attempt_id: &str,
) -> Result<SourceAdmissionPlan, String> {
    plan(vcs, ledger, host, witness_digest, attempt_id)
}

/// Compose the product Home's authoritative dependency capture. The installed
/// Home reader must bind its norm and reference bases; an injected graph or a
/// complete-looking extraction list cannot replace that authority.
#[cfg(feature = "native")]
pub fn plan_native_with_authority<L: AdmissionLedger, S: RuntimeStore>(
    vcs: &NativeWorkspaceVcs,
    ledger: &L,
    host: AdmissionHost<'_, S>,
    witness_digest: &str,
    attempt_id: &str,
    authority: &dyn ProcessCaptureAuthority,
) -> Result<SourceAdmissionPlan, String> {
    derive(
        vcs,
        ledger,
        host,
        witness_digest,
        attempt_id,
        SourceAdmissionCapture {
            home: Some(authority),
            review: None,
        },
    )
}

/// The same domain process over any owning VCS implementation. Hosted
/// readers do not substitute serialized manifests or replayed subjects.
pub fn plan<
    B: Branches + FlowingAdmissions + FlowingAbandonments + FlowingFence + FlowingSources,
    C: ContentBlobs,
    L: AdmissionLedger,
    S: RuntimeStore,
>(
    vcs: &WorkspaceVcs<B, C>,
    ledger: &L,
    host: AdmissionHost<'_, S>,
    witness_digest: &str,
    attempt_id: &str,
) -> Result<SourceAdmissionPlan, String> {
    derive(
        vcs,
        ledger,
        host,
        witness_digest,
        attempt_id,
        SourceAdmissionCapture::default(),
    )
}

pub fn plan_with_authority<
    B: Branches + FlowingAdmissions + FlowingAbandonments + FlowingFence + FlowingSources,
    C: ContentBlobs,
    L: AdmissionLedger,
    S: RuntimeStore,
>(
    vcs: &WorkspaceVcs<B, C>,
    ledger: &L,
    host: AdmissionHost<'_, S>,
    witness_digest: &str,
    attempt_id: &str,
    authority: &dyn ProcessCaptureAuthority,
) -> Result<SourceAdmissionPlan, String> {
    derive(
        vcs,
        ledger,
        host,
        witness_digest,
        attempt_id,
        SourceAdmissionCapture {
            home: Some(authority),
            review: None,
        },
    )
}

/// Compose independently installed Home and native review readers. The request
/// continues to select only retained witness and attempt coordinates.
pub fn plan_with_capture<
    B: Branches + FlowingAdmissions + FlowingAbandonments + FlowingFence + FlowingSources,
    C: ContentBlobs,
    L: AdmissionLedger,
    S: RuntimeStore,
>(
    vcs: &WorkspaceVcs<B, C>,
    ledger: &L,
    host: AdmissionHost<'_, S>,
    witness_digest: &str,
    attempt_id: &str,
    capture: SourceAdmissionCapture<'_>,
) -> Result<SourceAdmissionPlan, String> {
    derive(vcs, ledger, host, witness_digest, attempt_id, capture)
}

fn derive<
    B: Branches + FlowingAdmissions + FlowingAbandonments + FlowingFence + FlowingSources,
    C: ContentBlobs,
    L: AdmissionLedger,
    S: RuntimeStore,
>(
    vcs: &WorkspaceVcs<B, C>,
    ledger: &L,
    host: AdmissionHost<'_, S>,
    witness_digest: &str,
    attempt_id: &str,
    readers: SourceAdmissionCapture<'_>,
) -> Result<SourceAdmissionPlan, String> {
    let authority = readers.home;
    let process = process_identity()?;
    let mut captured = vcs
        .capture_gate_subject(witness_digest, attempt_id)
        .map_err(|error| format!("{error:?}"))?;
    let review_read = readers.review.map(|reader| {
        reader.capture_native_revision(
            &captured.witness().contribution_id,
            captured.witness().revision_sequence,
        )
    });
    let source_verification = match &review_read {
        Some(Ok(revision)) => {
            let verified = vcs
                .verify_retained_native_candidate(revision, witness_digest, attempt_id)
                .map_err(|error| format!("{error:?}"))?;
            captured = verified.subject().clone();
            Some(SourceCandidateVerification {
                review_revision: EvidenceVersion {
                    name: "whipplescript.native-review-revision".into(),
                    version: "1".into(),
                    digest: identity(&("native-review-revision-v1", revision))?,
                },
            })
        }
        // Invalid authority must refuse, rather than continuing with a gap.
        // MUTATION-SUCCESS-EXPR: None
        Some(Err(NativeReviewReadError::Invalid(reason))) => return Err(reason.clone()),
        _ => None,
    };
    if !ledger
        .bootstrapped()
        .map_err(|error| format!("{error:?}"))?
    {
        return Err("source admission has no admitted norm policy".into());
    }
    let (view, events) = ledger
        .capture(host.verifier)
        .map_err(|error| format!("{error:?}"))?;
    let history =
        CapturedNormHistory::capture(&view, &events, host.verifier, NormHistoryLimits::default())
            .map_err(|error| format!("{error:?}"))?;
    let witness = captured.witness();
    let capture = |cut: &str| vcs.capture_norm_artifact(cut, ArtifactLimits::default());
    let planned = crate::norm_planning::plan(
        ImpactQuery {
            configuration: host.configuration,
            history: &history,
            verifier: host.verifier,
            runtime: host.runtime,
            artifacts: &capture,
            before_cut: witness
                .expected_trunk_cut_id
                .as_deref()
                .unwrap_or(&witness.candidate_cut_id),
            after_cut: &witness.candidate_cut_id,
            before_frontier: None,
            after_frontier: None,
            policy: host.policy,
        },
        host.verify_runtime,
    )?;
    // Both the retained witness and the artifacts are read from this VCS's
    // authority at the exact witness cuts; no caller supplies a manifest.
    let inventory = inventory_at(&view).map_err(|error| format!("{error:?}"))?;
    let edges = observed_edges_at(&view).map_err(|error| format!("{error:?}"))?;
    let acts = observed_acts_at(&view);
    let references = LocalReferenceObservation {
        ledger: inventory.ledger,
        authority_head: inventory.authority_head,
        frontier: inventory.frontier,
        charter_digest: inventory.charter_digest.clone(),
        charter_events: inventory.charter_events,
        required_classes: inventory
            .fields
            .iter()
            .map(|field| ReferenceClassObservation {
                contract: EvidenceVersion {
                    name: format!("norm/{}/{}", field.vocabulary, field.path),
                    version: field.vocabulary_version.clone(),
                    digest: format!("sha256:{}", inventory.charter_digest),
                },
                vocabulary: field.vocabulary.clone(),
                version: field.vocabulary_version.clone(),
                field: field.path.clone(),
                meaning: field.meaning,
            })
            .collect(),
        observed_acts: acts
            .admissions
            .iter()
            .map(|act| act.event.clone())
            .collect(),
        edges: edges
            .references
            .iter()
            .map(|edge| ReferenceEdgeObservation {
                consumer: edge.consumer.clone(),
                consumer_revision: edge.consumer_revision.clone(),
                vocabulary: edge.vocabulary.name.clone(),
                vocabulary_version: edge.vocabulary.version.clone(),
                field: edge.field.clone(),
                occurrence: edge.occurrence.clone(),
                provider: edge.provider.clone(),
                resolved_revision: edge.resolved_revision.clone(),
                meaning: edge.meaning,
            })
            .collect(),
        historical_population_unknown: inventory.historical_population_unknown,
    };
    let mut blockers = BTreeSet::new();
    if source_verification.is_none() {
        blockers.insert(LocatedBlocker {
            scope: "source/review-record".into(),
            reason: match &review_read {
                Some(Err(NativeReviewReadError::Unavailable(reason))) => reason.clone(),
                _ => "no independently installed original native review reader was captured".into(),
            },
        });
    }
    let mut process_installation = None;
    let mut norm_binding = None;
    let dependencies = match authority {
        None => {
            blockers.insert(LocatedBlocker {
                scope: "home/process-installation".into(),
                reason:
                    "no independently admitted process policy or installed derivation was captured"
                        .into(),
            });
            blockers.insert(LocatedBlocker {
                scope: "home/reference-population".into(),
                reason: "no authoritative Home operation population, sealed cut or enforced scope boundary was captured".into(),
            });
            None
        }
        Some(authority) => match crate::source_process::capture_impact(authority, witness_digest) {
            Err(reason) => {
                blockers.insert(LocatedBlocker {
                    scope: "home/reference-population".into(),
                    reason,
                });
                None
            }
            Ok(impact) => {
                let installed = authority.verify_process_basis(&impact.basis, &process);
                if let Err(reason) = &installed {
                    blockers.insert(LocatedBlocker {
                        scope: "home/process-installation".into(),
                        reason: reason.clone(),
                    });
                }
                process_installation = Some(installed);
                if impact.basis.native_base_cut != witness.expected_trunk_cut_id
                    || impact.basis.native_candidate_cut != witness.candidate_cut_id
                {
                    blockers.insert(LocatedBlocker {
                        scope: "home/structural-cut".into(),
                        reason: "Home structural vector names another native base or candidate"
                            .into(),
                    });
                }
                let binding = authority.verify_norm_basis(
                    &impact.basis,
                    &planned.anchor,
                    &planned.plan.policy,
                );
                if let Err(reason) = &binding {
                    blockers.insert(LocatedBlocker {
                        scope: "home/norm-basis".into(),
                        reason: reason.clone(),
                    });
                }
                norm_binding = Some(binding);
                for class in &references.required_classes {
                    let scope = ReferenceScope {
                        class: class.contract.clone(),
                        consumer_scope: format!("norm/{}", references.ledger),
                    };
                    let population = impact.basis.after.scopes.get(&scope);
                    let records = view.records.values().filter(|record| {
                        record.vocabulary.name == class.vocabulary
                            && record.vocabulary.version == class.version
                    });
                    let mut missing = population.is_none();
                    for record in records {
                        let consumer = DependencyIdentity {
                            authority: references.ledger.clone(),
                            identity: record.id.clone(),
                        };
                        missing |= !population.is_some_and(|members| members.contains(&consumer))
                            || impact.basis.after.resolutions.get(&consumer) != Some(&record.head);
                    }
                    if missing {
                        blockers.insert(LocatedBlocker {
                            scope: format!("home/norm/{}/{}/{}", references.ledger, class.vocabulary, class.field),
                            reason: "Home registry or exact consumer population omits a locally required reference scope".into(),
                        });
                    }
                }
                for gap in &impact.blockers {
                    blockers.insert(LocatedBlocker {
                        scope: format!(
                            "home/{}/{}/{:?}",
                            impact.basis.home, gap.scope.consumer_scope, gap.side
                        ),
                        reason: gap.reason.clone(),
                    });
                }
                Some(impact)
            }
        },
    };
    for class in &references.required_classes {
        if class.meaning.is_none() {
            blockers.insert(LocatedBlocker {
                scope: format!(
                    "norm/{}/{}/{}/{}",
                    references.ledger, class.vocabulary, class.version, class.field
                ),
                reason: "reference-capable field has no admitted meaning".into(),
            });
        }
    }
    if references.historical_population_unknown {
        blockers.insert(LocatedBlocker {
            scope: format!("norm/{}/historical-population", references.ledger),
            reason: "current charter declarations do not close earlier accepting paths".into(),
        });
    }
    if let Err(refusal) = crate::norm_admission::judge(&planned) {
        blockers.insert(LocatedBlocker {
            scope: "norm/admission".into(),
            reason: refusal.reason(),
        });
    }
    for conflict in &planned.reservation_conflicts {
        blockers.insert(LocatedBlocker {
            scope: "norm/reservations".into(),
            reason: serde_json::to_string(conflict).map_err(|error| format!("{error:?}"))?,
        });
    }
    let mut dependency_work = BTreeMap::new();
    let mut dependency_judgments = BTreeMap::new();
    let mut validation_bindings = Vec::new();
    let obligations = obligations(witness_digest, &planned)?;
    if let (Some(impact), Some(authority)) = (&dependencies, authority) {
        for (consumer, validations) in &impact.validations {
            for validation in validations {
                let binding = authority.validation_requirement(&impact.basis, consumer, validation);
                let work = DependencyValidationWork {
                    consumer: consumer.clone(),
                    owner: validation.owner.clone(),
                    method: validation.method.clone(),
                    structural_cut: validation.candidate_cut.clone(),
                    binding: binding.as_ref().ok().cloned().flatten(),
                };
                let mut selected = validation_judgment(&work, &references.ledger, &obligations);
                if let Err(reason) = &binding {
                    selected.reason = Some(reason.clone());
                }
                let id = identity(&(
                    "source-dependency-validation-v1",
                    witness_digest,
                    &impact.basis,
                    &work,
                ))?;
                if selected.work != ImpactWork::Supported {
                    blockers.insert(LocatedBlocker {
                        scope: format!("dependency-validation/{id}"),
                        reason: selected.reason.clone().unwrap_or_else(|| {
                            format!("owning validation remains {:?}", selected.work)
                        }),
                    });
                }
                validation_bindings.push((consumer.clone(), validation.clone(), binding));
                dependency_judgments.insert(id.clone(), selected);
                dependency_work.insert(id, work);
            }
        }
    }
    let judgment = SourceAdmissionJudgment {
        protocol: "whipplescript.source-admission/v1",
        process,
        subject: SourceAdmissionSubject {
            witness_digest: witness_digest.into(),
            witness: witness.clone(),
            source_fence: captured.fence().clone(),
            lineage_fences: captured.lineage_fences().to_vec(),
            unit_holders: captured.unit_holders().to_vec(),
        },
        source_verification,
        interpretation: host.configuration.identity().clone(),
        norm: planned.to_json(),
        obligations,
        references,
        dependencies,
        dependency_work,
        dependency_judgments,
        blockers,
    };
    if let (Some(authority), Some(impact)) = (authority, &judgment.dependencies) {
        for (consumer, validation, captured) in validation_bindings {
            if authority.validation_requirement(&impact.basis, &consumer, &validation) != captured {
                return Err(
                    "Home owning validation correspondence changed during derivation".into(),
                );
            }
        }
        if Some(authority.verify_process_basis(&impact.basis, &judgment.process))
            != process_installation
        {
            return Err("Home process installation changed during derivation".into());
        }
        if Some(authority.verify_norm_basis(&impact.basis, &planned.anchor, &planned.plan.policy))
            != norm_binding
        {
            return Err("Home norm authority binding changed during derivation".into());
        }
        if authority.basis(witness_digest)? != impact.basis {
            return Err("Home source-admission basis changed during derivation".into());
        }
    }
    planned
        .method_installation
        .revalidate(host.runtime, host.verify_runtime)?;
    // Recapture after every Home and installation callback. These callbacks
    // may race a source or ledger change; this remains a query, not the final
    // publication exclusion. Read the source after the ledger callback too.
    let (current_view, current_events) = ledger
        .capture(host.verifier)
        .map_err(|error| format!("{error:?}"))?;
    let current_history = CapturedNormHistory::capture(
        &current_view,
        &current_events,
        host.verifier,
        NormHistoryLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let current_review = readers.review.map(|reader| {
        reader.capture_native_revision(
            &captured.witness().contribution_id,
            captured.witness().revision_sequence,
        )
    });
    if current_review != review_read {
        return Err("source review record changed during derivation".into());
    }
    // Re-run content and closure proof after the final ledger and review reads.
    // This is read-only recapture, not the production publication exclusion.
    if let Some(Ok(revision)) = &current_review {
        vcs.verify_retained_native_candidate(revision, witness_digest, attempt_id)
            .map_err(|error| format!("{error:?}"))?;
    }
    let current = vcs
        .capture_gate_subject(witness_digest, attempt_id)
        .map_err(|error| format!("{error:?}"))?;
    if current != captured || current_history.anchor() != planned.anchor {
        return Err("source-admission premises changed during derivation".into());
    }
    Ok(SourceAdmissionPlan {
        identity: identity(&judgment)?,
        judgment,
    })
}

#[cfg(all(test, feature = "native"))]
#[path = "source_admission_tests.rs"]
mod tests;
