//! Charter activation (norm-plane §10, slice W1): the preceding charter's
//! authority installs a successor, and the activation's migration plans every
//! live record — a successor under the new charter, retention under its old
//! vocabulary, or explicit retirement.
//!
//! A total plan is necessary but not sufficient. A successor must keep what
//! each live record's status means for effectiveness, keep its vocabulary's
//! relation, manifest, correspondence and inventory declarations, and keep
//! every admission its old vocabulary required unless the activation declares
//! the change. Anything short of that is a located obstruction, and one
//! obstruction refuses the activation, which then changes nothing.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use whipplescript_core::vocabulary::{AdmissionPredicate, Vocabulary, VocabularyRef};

use crate::norm::{NormCharter, NormRecord, NormView, NormVocabulary, RevisionEffect};
use crate::{StoreError, StoreResult};

/// A proposed activation: the successor charter, the plan for every live
/// record, and the admissions it declares changed. The act signs exactly this;
/// a host plans it first to learn every obstruction before anyone signs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationProposal {
    pub charter: NormCharter,
    pub migration: Vec<VocabularyMigration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<AuthorizedChange>,
}

/// What an activation does with the live records of one vocabulary in force.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VocabularyMigration {
    pub from: VocabularyRef,
    pub plan: MigrationPlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "plan", rename_all = "snake_case", deny_unknown_fields)]
pub enum MigrationPlan {
    /// Every live record moves to a vocabulary of the new charter, each old
    /// status to the one this total map names.
    Successor {
        vocabulary: VocabularyRef,
        statuses: BTreeMap<String, String>,
    },
    /// The new charter carries the vocabulary unchanged, and its records stay
    /// interpreted under it.
    Retain {},
    /// Every live record is closed under the preceding charter's authority:
    /// no longer effective, and no act admitted on it again.
    Retire {},
}

/// An admission a successor vocabulary changes, declared by the activation so
/// the preceding charter's authority is what authorizes it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedChange {
    /// The successor vocabulary that makes the change.
    pub vocabulary: VocabularyRef,
    pub rule: ChangedRule,
    pub rationale: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChangedRule {
    Creation {},
    Editing {},
    /// A step between two successor statuses, named in the successor's terms.
    Transition {
        from: String,
        to: String,
    },
}

impl ChangedRule {
    fn describe(&self) -> String {
        match self {
            Self::Creation {} => "creation".into(),
            Self::Editing {} => "editing".into(),
            Self::Transition { from, to } => format!("{from} -> {to}"),
        }
    }
}

/// One reason an activation cannot proceed, located at the vocabulary, and
/// where it has one the record or rule, that obstructs it.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ActivationObstruction {
    pub vocabulary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub reason: String,
}

fn label(reference: &VocabularyRef) -> String {
    format!("{}@{}", reference.name, reference.version)
}

fn refused(message: impl Into<String>) -> StoreError {
    StoreError::Conflict(message.into())
}

/// The refusal an obstructed activation carries: every obstruction, located.
pub fn obstruction_refusal(obstructions: &[ActivationObstruction]) -> StoreError {
    let located: Vec<String> = obstructions
        .iter()
        .map(|obstruction| {
            let mut at = obstruction.vocabulary.clone();
            if let Some(record) = &obstruction.record {
                at.push_str(&format!(" record {record}"));
            }
            if let Some(rule) = &obstruction.rule {
                at.push_str(&format!(" rule {rule}"));
            }
            format!("{at}: {}", obstruction.reason)
        })
        .collect();
    refused(format!(
        "charter activation is obstructed: {}",
        located.join("; ")
    ))
}

/// Whether one admission demands at least what another did: the same rule, a
/// public rule strengthened, or an authority's rule given a witness or an
/// arbitration under the same scope. Anything else changes who may act.
fn demands_at_least(successor: &AdmissionPredicate, old: &AdmissionPredicate) -> bool {
    if successor == old {
        return true;
    }
    match (old, successor) {
        (AdmissionPredicate::Public {}, _) => true,
        (
            AdmissionPredicate::Authority { scope },
            AdmissionPredicate::Witnessed { scope: kept, .. }
            | AdmissionPredicate::Arbitrated { scope: kept, .. },
        ) => scope == kept,
        _ => false,
    }
}

/// What a status means for a revision's effectiveness under one vocabulary:
/// `None` when the vocabulary declares no interpretation at all.
fn effect_of(entry: &NormVocabulary, status: &str) -> Option<Option<RevisionEffect>> {
    entry.effectiveness.as_ref().map(|rules| {
        rules
            .iter()
            .find(|rule| rule.status == status)
            .map(|rule| rule.effect)
    })
}

fn entry_for<'a>(
    charter: &'a NormCharter,
    reference: &VocabularyRef,
) -> Option<&'a NormVocabulary> {
    charter
        .vocabularies
        .iter()
        .find(|entry| same_version(entry, reference))
}

fn reference_of(entry: &NormVocabulary) -> StoreResult<VocabularyRef> {
    Ok(Vocabulary::new(entry.definition.clone())
        .map_err(|error| refused(error.to_string()))?
        .reference()
        .clone())
}

pub(crate) fn same_version(entry: &NormVocabulary, reference: &VocabularyRef) -> bool {
    entry.definition.name == reference.name && entry.definition.version == reference.version
}

impl NormView {
    /// Every record a charter activation retired.
    pub fn retired_records(&self) -> &BTreeSet<String> {
        &self.retired
    }

    /// Whether a charter activation retired this record.
    pub fn is_retired(&self, record: &str) -> bool {
        self.retired.contains(record)
    }

    /// Whether a record is still open: not retired by an activation, and in a
    /// status its vocabulary lets something leave. A closed record needs no
    /// plan and stays replayable under its original vocabulary.
    pub fn record_is_live(&self, record: &NormRecord) -> bool {
        if self.retired.contains(&record.id) {
            return false;
        }
        self.registry
            .get(&record.vocabulary)
            .is_ok_and(|vocabulary| {
                vocabulary
                    .definition()
                    .status
                    .transitions
                    .iter()
                    .any(|rule| rule.from == record.status)
            })
    }

    /// Everything that stops `charter` replacing the charter in force under
    /// this migration and these declared changes. An empty list means the
    /// activation may proceed; a malformed proposal is refused outright.
    pub fn activation_obstructions(
        &self,
        charter: &NormCharter,
        migration: &[VocabularyMigration],
        changes: &[AuthorizedChange],
    ) -> StoreResult<Vec<ActivationObstruction>> {
        crate::norm::registry_for(charter)?;
        // A version is immutable: a successor charter may repeat an earlier
        // declaration, never redefine it.
        for entry in &charter.vocabularies {
            let reference = reference_of(entry)?;
            if let Some(earlier) = self.interpretation(&reference) {
                if earlier != entry {
                    return Err(refused(format!(
                        "a successor charter redefines {}; a new definition needs a new version",
                        label(&reference)
                    )));
                }
            }
        }
        let mut planned: BTreeSet<String> = BTreeSet::new();
        for step in migration {
            if !planned.insert(label(&step.from)) {
                return Err(refused(format!(
                    "the migration plans {} twice",
                    label(&step.from)
                )));
            }
            let in_force = entry_for(&self.charter, &step.from)
                .map(|entry| reference_of(entry).is_ok_and(|reference| reference == step.from));
            if in_force != Some(true) {
                return Err(refused(format!(
                    "the migration plans {}, which is not in force",
                    label(&step.from)
                )));
            }
        }
        let mut declared = BTreeSet::new();
        for change in changes {
            if change.rationale.trim().is_empty() {
                return Err(refused("a declared change needs a rationale"));
            }
            if !declared.insert((label(&change.vocabulary), change.rule.clone())) {
                return Err(refused("a declared change is repeated"));
            }
        }

        let mut obstructions = Vec::new();
        // A gate is never released: a successor keeps every gated line.
        for line in &self.charter.gated_refs {
            if !charter.gated_refs.contains(line) {
                obstructions.push(ActivationObstruction {
                    vocabulary: "charter".into(),
                    record: None,
                    rule: Some(format!("gated ref {line}")),
                    reason: "a successor charter releases a gated line; a gate is never released"
                        .into(),
                });
            }
        }
        let mut used = BTreeSet::new();
        for entry in &self.charter.vocabularies {
            let from = reference_of(entry)?;
            let live: Vec<&NormRecord> = self
                .records
                .values()
                .filter(|record| record.vocabulary == from && self.record_is_live(record))
                .collect();
            let Some(step) = migration.iter().find(|step| step.from == from) else {
                for record in live {
                    obstructions.push(ActivationObstruction {
                        vocabulary: label(&from),
                        record: Some(record.id.clone()),
                        rule: None,
                        reason: "a live record has no migration plan".into(),
                    });
                }
                continue;
            };
            match &step.plan {
                MigrationPlan::Retire {} => {}
                MigrationPlan::Retain {} => {
                    if entry_for(charter, &from) != Some(entry) {
                        obstructions.push(ActivationObstruction {
                            vocabulary: label(&from),
                            record: None,
                            rule: None,
                            reason:
                                "a retained vocabulary must be carried unchanged by the new charter"
                                    .into(),
                        });
                    }
                }
                MigrationPlan::Successor {
                    vocabulary,
                    statuses,
                } => {
                    let Some(successor) = entry_for(charter, vocabulary).filter(|entry| {
                        reference_of(entry).is_ok_and(|exact| exact == *vocabulary)
                    }) else {
                        obstructions.push(ActivationObstruction {
                            vocabulary: label(&from),
                            record: None,
                            rule: None,
                            reason: format!(
                                "the successor {} is not in the new charter",
                                label(vocabulary)
                            ),
                        });
                        continue;
                    };
                    self.successor_obstructions(
                        entry,
                        &from,
                        successor,
                        vocabulary,
                        statuses,
                        &live,
                        &declared,
                        &mut used,
                        &mut obstructions,
                    )?;
                }
            }
        }
        for (vocabulary, rule) in declared.difference(&used) {
            obstructions.push(ActivationObstruction {
                vocabulary: vocabulary.clone(),
                record: None,
                rule: Some(rule.describe()),
                reason: "a declared change is not a change this activation makes".into(),
            });
        }
        obstructions.sort();
        Ok(obstructions)
    }

    #[allow(clippy::too_many_arguments)]
    fn successor_obstructions(
        &self,
        old: &NormVocabulary,
        from: &VocabularyRef,
        successor: &NormVocabulary,
        to: &VocabularyRef,
        statuses: &BTreeMap<String, String>,
        live: &[&NormRecord],
        declared: &BTreeSet<(String, ChangedRule)>,
        used: &mut BTreeSet<(String, ChangedRule)>,
        obstructions: &mut Vec<ActivationObstruction>,
    ) -> StoreResult<()> {
        let at = label(from);
        let mut obstruct = |record: Option<&str>, rule: Option<String>, reason: String| {
            obstructions.push(ActivationObstruction {
                vocabulary: at.clone(),
                record: record.map(str::to_owned),
                rule,
                reason,
            });
        };
        if to.name == from.name && to.version == from.version {
            obstruct(
                None,
                None,
                "a vocabulary cannot succeed itself; retain it instead".into(),
            );
            return Ok(());
        }
        let old_statuses: BTreeSet<&String> = old.definition.status.values.iter().collect();
        let mapped: BTreeSet<&String> = statuses.keys().collect();
        if old_statuses != mapped {
            obstruct(
                None,
                None,
                "the status map must name every status of the old vocabulary exactly once".into(),
            );
            return Ok(());
        }
        for (status, target) in statuses {
            if !successor.definition.status.values.contains(target) {
                obstruct(
                    None,
                    Some(format!("{status} -> {target}")),
                    format!("{target} is not a status of {}", label(to)),
                );
            }
        }
        // Interpretation the successor would silently change: a relation, a
        // manifest, a correspondence or an inventory role. A requirement that
        // loses its role would disappear from the inventory.
        if old.inventory_role != successor.inventory_role {
            let demoted = matches!(
                old.inventory_role,
                Some(crate::norm_inventory::InventoryRole::Requirement { .. })
            );
            obstruct(
                None,
                None,
                if demoted {
                    "a successor would demote a live requirement out of the inventory".into()
                } else {
                    "a successor changes the vocabulary's inventory role".into()
                },
            );
        }
        if old.relation != successor.relation
            || old.manifest != successor.manifest
            || old.correspondence != successor.correspondence
        {
            obstruct(
                None,
                None,
                "a successor changes a relation, manifest or correspondence declaration; retire and recreate its records instead".into(),
            );
        }
        let successor_vocabulary = Vocabulary::new(successor.definition.clone())
            .map_err(|error| refused(error.to_string()))?;
        for record in live {
            let target = &statuses[&record.status];
            if effect_of(old, &record.status) != effect_of(successor, target) {
                obstruct(
                    Some(&record.id),
                    None,
                    format!(
                        "{} -> {target} changes what the record's status means for its effectiveness",
                        record.status
                    ),
                );
            }
            if let Some(lifecycle) = self.effective_lifecycles.get(&record.id) {
                let effective_target = &statuses[&lifecycle.status];
                if effect_of(old, &lifecycle.status) != effect_of(successor, effective_target) {
                    obstruct(
                        Some(&record.id),
                        None,
                        format!(
                            "{} -> {effective_target} changes what the effective revision's status means",
                            lifecycle.status
                        ),
                    );
                }
            }
            if successor_vocabulary
                .validate_record(&record.fields, target)
                .is_err()
            {
                obstruct(
                    Some(&record.id),
                    None,
                    format!("the record's fields do not validate under {}", label(to)),
                );
            }
        }
        // Admissions: every rule the successor applies to a migrated record
        // demands at least what the old rule it replaces did, or the
        // activation declares the change.
        let mut declare = |rule: ChangedRule, reason: String| {
            let key = (label(to), rule.clone());
            if declared.contains(&key) {
                used.insert(key);
            } else {
                obstructions.push(ActivationObstruction {
                    vocabulary: at.clone(),
                    record: None,
                    rule: Some(rule.describe()),
                    reason,
                });
            }
        };
        if !demands_at_least(&successor.creation, &old.creation) {
            declare(
                ChangedRule::Creation {},
                "the successor weakens creation without a declared change".into(),
            );
        }
        match (&old.editing, &successor.editing) {
            (_, None) => {}
            (Some(old_rule), Some(rule)) if demands_at_least(rule, old_rule) => {}
            _ => declare(
                ChangedRule::Editing {},
                "the successor weakens editing without a declared change".into(),
            ),
        }
        let old_steps: BTreeMap<(&String, &String), &AdmissionPredicate> = old
            .definition
            .status
            .transitions
            .iter()
            .map(|rule| ((&rule.from, &rule.to), &rule.admission))
            .collect();
        let image: BTreeSet<&String> = statuses.values().collect();
        for rule in &successor.definition.status.transitions {
            if !image.contains(&rule.from) {
                continue;
            }
            let preimages: Vec<&AdmissionPredicate> = old_steps
                .iter()
                .filter(|((from, to), _)| {
                    statuses.get(*from) == Some(&rule.from) && statuses.get(*to) == Some(&rule.to)
                })
                .map(|(_, admission)| *admission)
                .collect();
            let changed = ChangedRule::Transition {
                from: rule.from.clone(),
                to: rule.to.clone(),
            };
            if preimages.is_empty() {
                declare(
                    changed,
                    "the successor adds a step migrated records could take without a declared change"
                        .into(),
                );
            } else if !preimages
                .iter()
                .all(|old_rule| demands_at_least(&rule.admission, old_rule))
            {
                declare(
                    changed,
                    "the successor weakens a step without a declared change".into(),
                );
            }
        }
        for (from_status, to_status) in old_steps.keys() {
            let (Some(a), Some(b)) = (statuses.get(*from_status), statuses.get(*to_status)) else {
                continue;
            };
            if a != b
                && !successor
                    .definition
                    .status
                    .transitions
                    .iter()
                    .any(|rule| &rule.from == a && &rule.to == b)
            {
                declare(
                    ChangedRule::Transition {
                        from: a.clone(),
                        to: b.clone(),
                    },
                    format!(
                        "the successor drops the step {from_status} -> {to_status} without a declared change"
                    ),
                );
            }
        }
        Ok(())
    }
}

/// How an activation leaves a running norm effect's late outcome
/// (norm-plane §10). The run is pinned to the requirement revision it was
/// prepared against; the requirement's own migration decides what that
/// revision still means.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum LateOutcome {
    /// The activation leaves the requirement's revision in force, so the
    /// outcome supports or refutes it as it would have.
    Kept {},
    /// The requirement moves to a successor vocabulary, and a successor is a
    /// new revision: the outcome evidences the pinned revision only, and the
    /// successor needs a run of its own.
    Pinned { successor: VocabularyRef },
    /// The requirement is retired: the outcome stays in the runtime journal
    /// and is not published.
    Retired {},
}

/// One running effect and what the activation makes of its late outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunningEffectPlan {
    pub effect: crate::norm_publication::RunningNormEffect,
    pub late: LateOutcome,
}

impl NormView {
    /// Plan every running norm effect into a proposed migration: each late
    /// outcome is kept, pinned or retired with its requirement. A publication
    /// already prepared is an obstruction, because its envelope names the
    /// authority epoch the activation closes and is never signed again, so
    /// activating first would strand it.
    pub fn plan_running_effects(
        &self,
        migration: &[VocabularyMigration],
        running: &[crate::norm_publication::RunningNormEffect],
    ) -> (Vec<RunningEffectPlan>, Vec<ActivationObstruction>) {
        let mut plans = Vec::new();
        let mut obstructions = Vec::new();
        for effect in running {
            let Some(record) = self.records.get(&effect.requirement) else {
                obstructions.push(ActivationObstruction {
                    vocabulary: "runtime".into(),
                    record: Some(effect.requirement.clone()),
                    rule: Some(format!("effect {}", effect.effect)),
                    reason: "a running effect names a requirement this ledger does not hold".into(),
                });
                continue;
            };
            if let Some(run) = &effect.prepared {
                obstructions.push(ActivationObstruction {
                    vocabulary: label(&record.vocabulary),
                    record: Some(record.id.clone()),
                    rule: Some(format!("effect {} run {run}", effect.effect)),
                    reason: "a publication prepared under the authority epoch this activation closes would be stranded; submit it first".into(),
                });
            }
            let step = migration.iter().find(|step| step.from == record.vocabulary);
            let late = match step.map(|step| &step.plan) {
                Some(MigrationPlan::Successor { vocabulary, .. })
                    if self.record_is_live(record) =>
                {
                    LateOutcome::Pinned {
                        successor: vocabulary.clone(),
                    }
                }
                Some(MigrationPlan::Retire {}) if self.record_is_live(record) => {
                    LateOutcome::Retired {}
                }
                _ if self.is_retired(&record.id) => LateOutcome::Retired {},
                _ => LateOutcome::Kept {},
            };
            plans.push(RunningEffectPlan {
                effect: effect.clone(),
                late,
            });
        }
        (plans, obstructions)
    }
}
