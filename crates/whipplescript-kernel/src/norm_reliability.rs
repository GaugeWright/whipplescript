//! Check reliability (norm-plane §3.5, slice N1), kept apart from conformance.
//!
//! Conformance says what the evidence supports. Reliability says whether the
//! method that produced it may carry a gated admission. A quarantined
//! method's positive support is not enough on its own: the requirement stays
//! blocking until support from a method in good standing, a statistical
//! policy fixed before the evidence it evaluates, or a scoped exception
//! resolves it. Quarantine never makes the requirement advisory, and it never
//! discards a counterexample: a failure is still counterevidence.
//!
//! A policy's window is every observation of the method, for the requirement
//! and artifact in question, whose run was prepared against a ledger frontier
//! that already held the policy's acceptance: the policy is fixed before the
//! evidence it evaluates. Every one counts: a pass as a pass, a counterexample
//! or a failed report as a failure, and a harness failure or a missing verdict
//! as a failure too. No run is left out, so a retry is one more observation and
//! never a reset, and no choice of which runs to count can wash a failure. The
//! window accepts once it holds at least `budget` runs of which no more than
//! `budget - threshold` failed to pass, and is rejected as soon as more than
//! that have.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use whipplescript_core::norm_evidence::{EvidenceVersion, TestOutcome};
use whipplescript_core::vocabulary::VocabularyRef;
use whipplescript_store::norm::{EffectiveRevision, NormRecord, NormView};

use crate::norm_impact::{ImpactPlan, ImpactWork};

/// The vocabularies a host interprets for reliability.
#[derive(Clone, Debug, Default)]
pub struct ReliabilityVocabularies {
    pub quarantines: BTreeSet<VocabularyRef>,
    pub policies: BTreeSet<VocabularyRef>,
    pub exceptions: BTreeSet<VocabularyRef>,
}

/// How a policy's window stands.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowVerdict {
    /// Full, with at least the threshold of passes.
    Accepted,
    /// Not yet full.
    Collecting,
    /// Full without the threshold of passes: unresolved for good under this
    /// policy; only a new policy, fixed before its own evidence, can recover
    /// the method.
    Rejected,
}

/// A sampling policy's window over one requirement and artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyWindow {
    pub policy: String,
    pub budget: u64,
    pub threshold: u64,
    pub passes: u64,
    pub failures: u64,
    pub missing: u64,
    /// The observations counted.
    pub counted: Vec<String>,
    pub verdict: WindowVerdict,
}

/// Why a quarantined method's support does not carry an admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuarantinedSupport {
    pub method: String,
    pub quarantine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<PolicyWindow>,
}

/// An exception a gate applies to one requirement (norm-plane §5).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppliedException {
    pub exception: String,
    pub scope: String,
    pub effects: String,
    pub residual: String,
    pub accountable: String,
    pub expires_at: String,
}

fn method_key(method: &EvidenceVersion) -> String {
    format!("{}@{}", method.name, method.version)
}

fn text<'a>(record: &'a NormRecord, field: &str) -> Option<&'a str> {
    record.fields.get(field).and_then(serde_json::Value::as_str)
}

/// The effective records of these vocabularies, with the act that made each
/// effective.
fn effective<'a>(
    view: &'a NormView,
    vocabularies: &BTreeSet<VocabularyRef>,
) -> Vec<(&'a NormRecord, String)> {
    view.records
        .values()
        .filter(|record| vocabularies.contains(&record.vocabulary))
        .filter_map(|record| match view.effective_revision(record) {
            EffectiveRevision::Active { record, lifecycle } => {
                Some((view.effective_records.get(&record.id)?, lifecycle.head))
            }
            _ => None,
        })
        .collect()
}

/// One observation of a method: its event, how it came out, and whether its
/// run was prepared after a given act.
type Observation = (String, TestOutcome, bool, bool);

/// Judge a policy's window over the observations of one method whose runs
/// were prepared after the policy became effective.
fn window(
    policy: &NormRecord,
    activation: &str,
    observations: &[Observation],
    prepared_after: &dyn Fn(&str, &str) -> bool,
) -> Option<PolicyWindow> {
    let budget = policy.fields.get("budget")?.as_u64()?;
    let threshold = policy.fields.get("threshold")?.as_u64()?;
    let mut result = PolicyWindow {
        policy: policy.id.clone(),
        budget,
        threshold,
        passes: 0,
        failures: 0,
        missing: 0,
        counted: Vec::new(),
        verdict: WindowVerdict::Collecting,
    };
    for (event, outcome, counterexample, diagnosed) in observations {
        if !prepared_after(event, activation) {
            continue;
        }
        match (outcome, counterexample, diagnosed) {
            (_, true, _) | (TestOutcome::Fail, _, _) => result.failures += 1,
            (TestOutcome::Pass, false, false) => result.passes += 1,
            _ => result.missing += 1,
        }
        result.counted.push(event.clone());
    }
    let tolerated = budget.saturating_sub(threshold);
    let unpassed = result.failures + result.missing;
    result.verdict = if unpassed > tolerated {
        WindowVerdict::Rejected
    } else if result.counted.len() as u64 >= budget {
        WindowVerdict::Accepted
    } else {
        WindowVerdict::Collecting
    };
    Some(result)
}

/// Apply reliability to a plan: a requirement whose only positive support
/// comes from quarantined methods is not supported, unless a policy window
/// over the method has accepted. `prepared_after(observation, act)` says
/// whether the observation's run was prepared against a frontier holding `act`.
pub fn apply(
    plan: &mut ImpactPlan,
    view: &NormView,
    vocabularies: &ReliabilityVocabularies,
    prepared_after: &dyn Fn(&str, &str) -> bool,
) {
    let quarantined: BTreeMap<String, String> = effective(view, &vocabularies.quarantines)
        .into_iter()
        .filter_map(|(record, _)| Some((text(record, "method")?.to_owned(), record.id.clone())))
        .collect();
    if quarantined.is_empty() {
        return;
    }
    let policies: Vec<(&NormRecord, String)> = effective(view, &vocabularies.policies);
    for impacts in plan.requirements.values_mut() {
        for impact in impacts.iter_mut() {
            if impact.work != ImpactWork::Supported {
                continue;
            }
            let Some(selection) = &impact.selection else {
                continue;
            };
            let methods: BTreeSet<String> = selection
                .positive
                .iter()
                .filter_map(|id| selection.judgments.get(id))
                .map(|judgment| method_key(&judgment.subject.method))
                .collect();
            // Support from any method in good standing carries the admission.
            if methods
                .iter()
                .any(|method| !quarantined.contains_key(method))
            {
                continue;
            }
            // Every positive comes from a quarantined method: one of them
            // recovers the support when a policy window over it has accepted.
            let mut blocked = None;
            for method in methods {
                let observations: Vec<Observation> = selection
                    .judgments
                    .iter()
                    .filter(|(_, judgment)| {
                        method_key(&judgment.subject.method) == method
                            && judgment.subject.requirement == selection.query.requirement
                            && judgment.subject.artifact == selection.query.artifact
                    })
                    .map(|(event, judgment)| {
                        (
                            event.clone(),
                            judgment.outcome,
                            !judgment.counterexamples.is_empty(),
                            !judgment.diagnostics.is_empty(),
                        )
                    })
                    .collect();
                let window = policies
                    .iter()
                    .filter(|(policy, _)| text(policy, "method") == Some(method.as_str()))
                    .filter_map(|(policy, activation)| {
                        window(policy, activation, &observations, prepared_after)
                    })
                    .max_by_key(|window| window.verdict == WindowVerdict::Accepted);
                if window
                    .as_ref()
                    .is_some_and(|window| window.verdict == WindowVerdict::Accepted)
                {
                    blocked = None;
                    break;
                }
                blocked.get_or_insert(QuarantinedSupport {
                    quarantine: quarantined[&method].clone(),
                    method,
                    window,
                });
            }
            if let Some(blocked) = blocked {
                impact.work = ImpactWork::Quarantined(Box::new(blocked));
            }
        }
    }
}

/// The exceptions a gate applies at a target ref, by requirement: granted,
/// scoped to that ref, and unexpired on the host's clock. Without a clock no
/// exception applies, since an exception relaxes a gate.
pub fn exceptions(
    view: &NormView,
    vocabularies: &ReliabilityVocabularies,
    target_ref: &str,
    now: Option<&str>,
) -> BTreeMap<String, AppliedException> {
    let Some(now) = now else {
        return BTreeMap::new();
    };
    let mut applied = BTreeMap::new();
    for (record, _) in effective(view, &vocabularies.exceptions) {
        let (Some(requirement), Some(scope), Some(expires_at)) = (
            text(record, "requirement"),
            text(record, "scope"),
            text(record, "expires_at"),
        ) else {
            continue;
        };
        let unexpired = matches!(
            (
                whipplescript_store::norm_reservations::instant(expires_at),
                whipplescript_store::norm_reservations::instant(now),
            ),
            (Some(expires), Some(now)) if expires > now
        );
        if scope != target_ref || !unexpired {
            continue;
        }
        applied.insert(
            requirement.to_owned(),
            AppliedException {
                exception: record.id.clone(),
                scope: scope.to_owned(),
                effects: text(record, "effects").unwrap_or_default().to_owned(),
                residual: text(record, "residual").unwrap_or_default().to_owned(),
                accountable: text(record, "accountable").unwrap_or_default().to_owned(),
                expires_at: expires_at.to_owned(),
            },
        );
    }
    applied
}

/// A method whose runs on one artifact need investigating (norm-plane §3.5):
/// a harness failure, or a pass and a counterexample under matching premises,
/// which marks the method's determinism `suspect`. Filing one is a workflow
/// act; `nonce` makes it durable and deduplicated by the family and contract
/// version (the method's full identity) and the artifact, because the ledger
/// admits one event per principal and nonce.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Investigation {
    pub method: EvidenceVersion,
    pub artifact: String,
    pub suspect: bool,
    pub harness_failed: bool,
    pub observations: Vec<String>,
    pub nonce: String,
}

/// One observation as investigation reads it.
pub struct Observed<'a> {
    pub event: &'a str,
    pub method: &'a EvidenceVersion,
    pub artifact: &'a str,
    pub outcome: &'a TestOutcome,
    pub counterexample: bool,
    pub diagnosed: bool,
}

/// A method's full identity and an artifact.
type InvestigationKey = (String, String, String, String);
/// Whether any run passed, failed or hit a harness failure, the runs, and the
/// method they share.
type InvestigationGroup<'a> = (bool, bool, bool, Vec<String>, &'a EvidenceVersion);

/// The investigations these observations call for, one per method and
/// artifact.
pub fn investigations<'a>(observed: impl IntoIterator<Item = Observed<'a>>) -> Vec<Investigation> {
    use sha2::{Digest, Sha256};
    let mut groups: BTreeMap<InvestigationKey, InvestigationGroup> = BTreeMap::new();
    for observation in observed {
        let key = (
            observation.method.name.clone(),
            observation.method.version.clone(),
            observation.method.digest.clone(),
            observation.artifact.to_owned(),
        );
        let entry =
            groups
                .entry(key)
                .or_insert((false, false, false, Vec::new(), observation.method));
        let passed = *observation.outcome == TestOutcome::Pass
            && !observation.counterexample
            && !observation.diagnosed;
        entry.0 |= passed;
        entry.1 |= observation.counterexample;
        entry.2 |= *observation.outcome == TestOutcome::HarnessFailed || observation.diagnosed;
        entry.3.push(observation.event.to_owned());
    }
    groups
        .into_iter()
        .filter_map(
            |((name, version, digest, artifact), (passed, failed, harness, mut events, method))| {
                let suspect = passed && failed;
                if !suspect && !harness {
                    return None;
                }
                events.sort();
                let mut hash = Sha256::new();
                hash.update(b"whipplescript.norm.investigation/v1\0");
                for part in [&name, &version, &digest, &artifact] {
                    hash.update(part.as_bytes());
                    hash.update(b"\0");
                }
                let nonce = format!(
                    "investigate-{}",
                    hash.finalize()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                );
                Some(Investigation {
                    method: method.clone(),
                    artifact,
                    suspect,
                    harness_failed: harness,
                    observations: events,
                    nonce,
                })
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_core::vocabulary::VocabularyRef;

    fn policy(budget: u64, threshold: u64) -> NormRecord {
        NormRecord {
            id: "policy".into(),
            vocabulary: VocabularyRef {
                name: "sampling-policy".into(),
                version: "1".into(),
                digest: "d".into(),
            },
            fields: serde_json::json!({"method": "q0@1", "budget": budget, "threshold": threshold}),
            content_head: "policy".into(),
            status: "accepted".into(),
            head: "accept".into(),
        }
    }

    fn pass(id: &str) -> Observation {
        (id.to_owned(), TestOutcome::Pass, false, false)
    }
    fn fail(id: &str) -> Observation {
        (id.to_owned(), TestOutcome::Fail, true, false)
    }
    fn harness(id: &str) -> Observation {
        (id.to_owned(), TestOutcome::HarnessFailed, false, true)
    }

    /// Every run but `before` was prepared after the policy's acceptance.
    fn after(observation: &str, activation: &str) -> bool {
        activation == "accept" && observation != "before"
    }

    #[test]
    fn a_window_counts_every_run_prepared_under_its_policy_and_never_resets() {
        let judge = |budget, threshold, runs: &[Observation]| {
            window(&policy(budget, threshold), "accept", runs, &after).unwrap()
        };
        // A run prepared before the policy was fixed does not count; three
        // passes prepared after it fill a budget of three at its threshold.
        let accepted = judge(3, 3, &[pass("before"), pass("r1"), pass("r2"), pass("r3")]);
        assert_eq!(accepted.verdict, WindowVerdict::Accepted);
        assert_eq!(accepted.counted, ["r1", "r2", "r3"]);
        // A failure stays counted whatever follows it: more passes are more
        // runs, not a retry that resets the window.
        let failed = judge(3, 3, &[fail("r1"), pass("r2"), pass("r3"), pass("r4")]);
        assert_eq!(failed.verdict, WindowVerdict::Rejected);
        assert_eq!((failed.passes, failed.failures, failed.missing), (3, 1, 0));
        // A harness failure is a missing run, and a missing run is not a pass.
        let missing = judge(3, 3, &[pass("r1"), harness("r2"), pass("r3"), pass("r4")]);
        assert_eq!(missing.verdict, WindowVerdict::Rejected);
        assert_eq!(
            (missing.passes, missing.failures, missing.missing),
            (3, 0, 1)
        );
        // A threshold below the budget tolerates what the policy declares,
        // and no more.
        assert_eq!(
            judge(3, 2, &[pass("r1"), harness("r2"), pass("r3")]).verdict,
            WindowVerdict::Accepted
        );
        assert_eq!(
            judge(3, 2, &[pass("r1"), harness("r2"), fail("r3"), pass("r4")]).verdict,
            WindowVerdict::Rejected
        );
        // Short of its budget, and within its tolerance, it is collecting.
        assert_eq!(
            judge(3, 3, &[pass("r1"), pass("r2")]).verdict,
            WindowVerdict::Collecting
        );
    }

    #[test]
    fn an_investigation_is_one_per_method_and_artifact_and_its_nonce_is_their_identity() {
        let method = EvidenceVersion {
            name: "q0".into(),
            version: "1".into(),
            digest: "a".into(),
        };
        let revised = EvidenceVersion {
            digest: "b".into(),
            ..method.clone()
        };
        let observed = |event, method, artifact, outcome, counterexample, diagnosed| Observed {
            event,
            method,
            artifact,
            outcome,
            counterexample,
            diagnosed,
        };
        let found = investigations([
            // A pass and a counterexample on one artifact: suspect.
            observed("r1", &method, "a1", &TestOutcome::Pass, false, false),
            observed("r2", &method, "a1", &TestOutcome::Fail, true, false),
            // A harness failure on another.
            observed(
                "r3",
                &method,
                "a2",
                &TestOutcome::HarnessFailed,
                false,
                true,
            ),
            // Consistent passes need nothing.
            observed("r4", &method, "a3", &TestOutcome::Pass, false, false),
            observed("r5", &method, "a3", &TestOutcome::Pass, false, false),
            // A revised contract is a different family version.
            observed(
                "r6",
                &revised,
                "a1",
                &TestOutcome::HarnessFailed,
                false,
                true,
            ),
        ]);
        assert_eq!(found.len(), 3, "{found:?}");
        let suspect = &found[0];
        assert!(suspect.suspect && !suspect.harness_failed);
        assert_eq!(suspect.observations, ["r1", "r2"]);
        assert!(found[1].harness_failed && found[1].artifact == "a2");
        assert_eq!(found[2].method.digest, "b");
        let nonces: BTreeSet<&String> = found.iter().map(|found| &found.nonce).collect();
        assert_eq!(nonces.len(), 3, "each identity has its own nonce");
        // The nonce is the identity's, not the runs': more runs, same nonce.
        let again = investigations([
            observed("r7", &method, "a1", &TestOutcome::Fail, true, false),
            observed("r8", &method, "a1", &TestOutcome::Pass, false, false),
            observed("r9", &method, "a1", &TestOutcome::Pass, false, false),
        ]);
        assert_eq!(again[0].nonce, suspect.nonce);
    }
}
