//! Admission onto a gated ref (norm-plane §5, G1): the one predicate every
//! door onto the mainline passes through.
//!
//! Preparation is pure. It plans impact from the base the ref would move from
//! to the exact proposed result, at the ledger's current frontier, and admits
//! only when every gated requirement — the base's duties and the candidate's
//! alike — is supported there, with no evidence, method or authority gap. What
//! it admitted is a certificate pinning the ledger state every ledger premise
//! was read at: charter, authority, requirements, evidence and its selection
//! all derive from that state, so it is the premise the commit re-checks.
//!
//! The commit holds the ledger's write exclusion, re-reads its state, and moves
//! the ref by compare-and-swap only if the state is the certified one; the
//! ref's own compare-and-swap covers the base head. Nothing that changes a
//! ledger premise can land between the check and the move (the
//! `admission-commit` model). A workspace with no norm ledger has no gated
//! requirement, and its certificate says so; a host that holds a ledger but
//! cannot evaluate it refuses and says why.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use whipplescript_store::items::TrackerEvent;
#[cfg(feature = "native")]
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::{NormVerifier, NormView};
use whipplescript_store::norm_commands::NormArtifactCapture;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits, NormReadAnchor};
use whipplescript_store::vcs::{GateCommit, GateRefusal, GateVerdict, MainlineGate};
use whipplescript_store::{RuntimeStore, StoreError, StoreResult};

use crate::norm_execution_policy::ProtectedPythonPolicy;
use crate::norm_impact::ImpactWork;
use crate::norm_planning::{ImpactQuery, Planned, PlanningConfiguration};
use crate::norm_runner::PythonRuntime;

/// Which door is asking. Enforcement attaches to the ref, so every door onto
/// a gated ref asks the same predicate; the door is recorded on the
/// certificate for the receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDoor {
    Promote,
    Transport,
    Undo,
    Restore,
    Merge,
    Adopt,
}

/// What an admission certified: the proposal, and the ledger state its
/// premises were read at.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionCertificate {
    pub door: AdmissionDoor,
    pub target_ref: String,
    pub base_cut: Option<String>,
    pub proposed_cut: String,
    /// None for a workspace with no norm ledger, which gates nothing.
    pub anchor: Option<NormReadAnchor>,
    /// The gated requirements judged, every one supported.
    pub requirements: BTreeSet<String>,
    /// The evidence selected in their support.
    pub evidence: BTreeSet<String>,
    /// Each exclusive reservation the proposal's changes fall under, with
    /// the current token the requester presented for it (norm-plane §7).
    pub reservations: BTreeMap<String, String>,
}

/// Why a proposal was refused, named by what it lacks.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct AdmissionRefusal {
    /// Each gated requirement that is not supported at the proposed result,
    /// with the work its support still needs.
    pub requirements: BTreeMap<String, Vec<String>>,
    /// Published evidence the host could not interpret.
    pub evidence_gaps: BTreeSet<String>,
    /// Requirements with no installed method to check them.
    pub method_gaps: BTreeSet<String>,
    /// Authority acts the proposal needs before it can be judged.
    pub authority_actions: Vec<String>,
    /// Exclusive reservations the proposal's changes fall under whose
    /// current token the requester did not present, with why.
    pub reservations: BTreeMap<String, String>,
    /// A premise the host could not establish at all.
    pub unevaluated: Option<String>,
}

impl AdmissionRefusal {
    pub fn reason(&self) -> String {
        if let Some(unevaluated) = &self.unevaluated {
            return format!("the mainline's gated requirements cannot be evaluated: {unevaluated}");
        }
        let mut named: Vec<String> = self
            .requirements
            .iter()
            .map(|(requirement, work)| format!("{requirement} ({})", work.join(", ")))
            .collect();
        named.extend(
            self.evidence_gaps
                .iter()
                .map(|event| format!("uninterpretable evidence {event}")),
        );
        named.extend(
            self.method_gaps
                .iter()
                .map(|requirement| format!("{requirement} (no installed method)")),
        );
        named.extend(self.authority_actions.iter().cloned());
        named.extend(
            self.reservations
                .iter()
                .map(|(reservation, why)| format!("reservation {reservation} ({why})")),
        );
        format!("the proposed result is not supported: {}", named.join("; "))
    }

    fn into_gate(self) -> GateRefusal {
        GateRefusal {
            reason: self.reason(),
            detail: serde_json::to_value(&self).unwrap_or(serde_json::Value::Null),
        }
    }
}

fn work_name(work: &ImpactWork) -> String {
    serde_json::to_value(work)
        .ok()
        .and_then(|value| {
            value
                .get("kind")
                .and_then(|k| k.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("{work:?}"))
}

/// Judge a plan: admissible only when every requirement, on either basis, is
/// supported and nothing about the plan is unresolved.
pub fn judge(
    planned: &Planned,
) -> Result<(BTreeSet<String>, BTreeSet<String>), Box<AdmissionRefusal>> {
    let mut refusal = AdmissionRefusal {
        evidence_gaps: planned.plan.evidence_gaps.keys().cloned().collect(),
        method_gaps: planned.method_gaps.keys().cloned().collect(),
        authority_actions: planned
            .plan
            .authority_actions
            .iter()
            .map(|action| format!("{action:?}"))
            .collect(),
        ..AdmissionRefusal::default()
    };
    let mut requirements = BTreeSet::new();
    let mut evidence = BTreeSet::new();
    for (requirement, impacts) in &planned.plan.requirements {
        requirements.insert(requirement.clone());
        for impact in impacts {
            if impact.work == ImpactWork::Supported {
                if let Some(selection) = &impact.selection {
                    evidence.extend(selection.positive.iter().cloned());
                }
            } else {
                refusal
                    .requirements
                    .entry(requirement.clone())
                    .or_default()
                    .push(work_name(&impact.work));
            }
        }
    }
    if refusal == AdmissionRefusal::default() {
        Ok((requirements, evidence))
    } else {
        Err(Box::new(refusal))
    }
}

/// Every path whose content differs between two captured results.
fn changed_paths(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    before
        .keys()
        .chain(after.keys())
        .filter(|path| before.get(*path) != after.get(*path))
        .cloned()
        .collect()
}

/// Whether a reservation selector covers a path, future members included
/// (norm-plane §7): `dir/**` is the subtree, `**` everything, and any other
/// pattern the gate cannot resolve conservatively covers every path.
fn covers(selector: &str, path: &str) -> bool {
    if let Some(root) = selector.strip_suffix("/**") {
        return path == root || path.starts_with(&format!("{root}/"));
    }
    selector == path || selector.contains('*')
}

/// The exclusive reservations a proposal's changes fall under (norm-plane
/// §7), split into those whose current token the requester presented — a
/// grant's token is its record's head, so any later act on the grant
/// rotates it — and those it did not, with why.
fn fence(
    view: &whipplescript_store::norm::NormView,
    reservations: &BTreeSet<whipplescript_core::vocabulary::VocabularyRef>,
    changed: &BTreeSet<String>,
    presented: &BTreeSet<String>,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut fenced = BTreeMap::new();
    let mut unfenced = BTreeMap::new();
    for (id, record) in &view.records {
        if !reservations.contains(&record.vocabulary)
            || record.status != "granted"
            || record.fields["mode"] != "exclusive"
        {
            continue;
        }
        let selectors: Vec<&str> = record.fields["selectors"]
            .as_array()
            .map(|selectors| selectors.iter().filter_map(|s| s.as_str()).collect())
            .unwrap_or_default();
        let Some(path) = changed
            .iter()
            .find(|path| selectors.iter().any(|selector| covers(selector, path)))
        else {
            continue;
        };
        if presented.contains(&record.head) {
            fenced.insert(id.clone(), record.head.clone());
        } else {
            unfenced.insert(
                id.clone(),
                format!("{path} is reserved, and its current token was not presented"),
            );
        }
    }
    (fenced, unfenced)
}

/// The norm ledger as an admission needs it: its state, and a way to hold
/// every write to it off while a ref moves.
pub trait AdmissionLedger {
    /// Whether the workspace has bootstrapped a norm ledger at all.
    fn bootstrapped(&self) -> StoreResult<bool>;
    /// The verified current view and the whole history it was replayed from.
    fn capture(&self, verifier: &dyn NormVerifier) -> StoreResult<(NormView, Vec<TrackerEvent>)>;
    /// Run `f` with every write to the ledger excluded until it returns.
    fn exclusively(
        &self,
        f: &mut dyn FnMut() -> StoreResult<GateCommit>,
    ) -> StoreResult<GateCommit>;
}

#[cfg(feature = "native")]
impl AdmissionLedger for WorkItemStore {
    fn bootstrapped(&self) -> StoreResult<bool> {
        Ok(self.norm_checkpoint()?.is_some())
    }
    fn capture(&self, verifier: &dyn NormVerifier) -> StoreResult<(NormView, Vec<TrackerEvent>)> {
        Ok((self.norm_view(verifier)?, self.export_events()?))
    }
    fn exclusively(
        &self,
        f: &mut dyn FnMut() -> StoreResult<GateCommit>,
    ) -> StoreResult<GateCommit> {
        self.with_norm_write_exclusion(f)
    }
}

/// What a host supplies to evaluate its gated requirements.
pub struct AdmissionHost<'a, S: RuntimeStore> {
    pub verifier: &'a dyn NormVerifier,
    pub configuration: &'a PlanningConfiguration,
    pub runtime: &'a S,
    pub policy: &'a ProtectedPythonPolicy,
    pub verify_runtime: &'a dyn Fn(&PythonRuntime) -> Result<(), String>,
}

/// The norm-plane gate on the mainline, over one host's ledger.
pub struct NormMainlineAdmission<'a, L: AdmissionLedger, S: RuntimeStore> {
    ledger: &'a L,
    /// The host's evaluation inputs, or why it has none.
    host: Result<AdmissionHost<'a, S>, String>,
    door: AdmissionDoor,
    target_ref: String,
    /// The reservation tokens the requester presents.
    tokens: BTreeSet<String>,
    certificate: Option<AdmissionCertificate>,
}

impl<'a, L: AdmissionLedger, S: RuntimeStore> NormMainlineAdmission<'a, L, S> {
    pub fn new(
        ledger: &'a L,
        host: Result<AdmissionHost<'a, S>, String>,
        door: AdmissionDoor,
        target_ref: &str,
    ) -> Self {
        Self {
            ledger,
            host,
            door,
            target_ref: target_ref.to_owned(),
            tokens: BTreeSet::new(),
            certificate: None,
        }
    }

    /// Present the requester's reservation tokens (norm-plane §7).
    pub fn with_tokens(mut self, tokens: impl IntoIterator<Item = String>) -> Self {
        self.tokens = tokens.into_iter().collect();
        self
    }

    /// What the last preparation certified, for the door's receipt.
    pub fn certificate(&self) -> Option<&AdmissionCertificate> {
        self.certificate.as_ref()
    }

    fn state(&self) -> StoreResult<Option<NormReadAnchor>> {
        if !self.ledger.bootstrapped()? {
            return Ok(None);
        }
        let host = self
            .host
            .as_ref()
            .map_err(|reason| StoreError::Conflict(reason.clone()))?;
        let (view, events) = self.ledger.capture(host.verifier)?;
        let history = CapturedNormHistory::capture(
            &view,
            &events,
            host.verifier,
            NormHistoryLimits::default(),
        )?;
        Ok(Some(history.anchor()))
    }
}

impl<L: AdmissionLedger, S: RuntimeStore> MainlineGate for NormMainlineAdmission<'_, L, S> {
    fn prepare(
        &mut self,
        base_cut: Option<&str>,
        proposed_cut: &str,
        artifacts: &NormArtifactCapture<'_>,
    ) -> StoreResult<GateVerdict> {
        self.certificate = None;
        let mut certificate = AdmissionCertificate {
            door: self.door,
            target_ref: self.target_ref.clone(),
            base_cut: base_cut.map(str::to_owned),
            proposed_cut: proposed_cut.to_owned(),
            anchor: None,
            requirements: BTreeSet::new(),
            evidence: BTreeSet::new(),
            reservations: BTreeMap::new(),
        };
        if !self.ledger.bootstrapped()? {
            self.certificate = Some(certificate);
            return Ok(GateVerdict::Admit);
        }
        let host = match &self.host {
            Ok(host) => host,
            Err(reason) => {
                return Ok(GateVerdict::Refuse(
                    AdmissionRefusal {
                        unevaluated: Some(reason.clone()),
                        ..AdmissionRefusal::default()
                    }
                    .into_gate(),
                ))
            }
        };
        let (view, events) = self.ledger.capture(host.verifier)?;
        let history = CapturedNormHistory::capture(
            &view,
            &events,
            host.verifier,
            NormHistoryLimits::default(),
        )?;
        // A mainline with no head yet has no base duties of its own; the
        // candidate is judged on both sides.
        let planned = crate::norm_planning::plan(
            ImpactQuery {
                configuration: host.configuration,
                history: &history,
                verifier: host.verifier,
                runtime: host.runtime,
                artifacts,
                before_cut: base_cut.unwrap_or(proposed_cut),
                after_cut: proposed_cut,
                before_frontier: None,
                after_frontier: None,
                policy: host.policy,
            },
            host.verify_runtime,
        )
        .map_err(StoreError::Conflict)?;
        let changed = changed_paths(
            &match base_cut {
                Some(base) => artifacts(base)?.files().clone(),
                None => BTreeMap::new(),
            },
            artifacts(proposed_cut)?.files(),
        );
        let (fenced, unfenced) = fence(
            &view,
            host.configuration.reservation_vocabularies(),
            &changed,
            &self.tokens,
        );
        match judge(&planned) {
            Ok((requirements, evidence)) if unfenced.is_empty() => {
                certificate.anchor = Some(planned.anchor.clone());
                certificate.requirements = requirements;
                certificate.evidence = evidence;
                certificate.reservations = fenced;
                self.certificate = Some(certificate);
                Ok(GateVerdict::Admit)
            }
            Ok(_) => Ok(GateVerdict::Refuse(
                AdmissionRefusal {
                    reservations: unfenced,
                    ..AdmissionRefusal::default()
                }
                .into_gate(),
            )),
            Err(refusal) => Ok(GateVerdict::Refuse(
                AdmissionRefusal {
                    reservations: unfenced,
                    ..*refusal
                }
                .into_gate(),
            )),
        }
    }

    fn commit(&mut self, advance: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<GateCommit> {
        let certified = self
            .certificate
            .as_ref()
            .map(|certificate| certificate.anchor.clone())
            .ok_or_else(|| StoreError::Conflict("the mainline gate has no certificate".into()))?;
        let this = &*self;
        this.ledger.exclusively(&mut || {
            if this.state()? != certified {
                return Ok(GateCommit::Stale {
                    changed: "the norm ledger changed after the admission was prepared".into(),
                });
            }
            advance()?;
            Ok(GateCommit::Committed)
        })
    }
}

#[cfg(all(test, feature = "native"))]
#[path = "norm_admission_tests.rs"]
mod tests;
