//! Structural views over a named frontier (norm-plane §8.1; the operating-model
//! note's stage 3, the Q1 subset).
//!
//! Three pure projections of one verified view: a manifest rendered as a
//! readable document, the diff of meaning between two frontiers over
//! whole-record revisions, and the explanation of one record, whose every
//! node is an obligation, a revision, evidence, a premise or an authority and
//! names the basis it was read at. None of them runs a check, admits anything
//! or reads outside the captured history, and none of them has an unqualified
//! "current": the frontier is part of the result.
//!
//! The renderer carries the manifest's derived completeness judgment and
//! derives nothing from the members it can see, so a rendering can never
//! present visible members as the complete inventory. The diff classifies a
//! revision by the declaration's own field classification: a change confined
//! to editorial fields rewords the record, any other change changes its
//! meaning, and a field the declaration does not classify is meaning.
//! Section identity inside a prose document waits for C1; these views work
//! over whole-record revisions.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use whipplescript_core::vocabulary::{AdmissionPredicate, VocabularyRef};

use crate::norm::{EffectiveRevision, NormPremises, NormRecord, NormStatement, NormView};
use crate::norm_manifests::{ManifestCompleteness, ManifestJudgment};
use crate::norm_relations::RelationEdge;
use crate::{StoreError, StoreResult};

/// What a view is read from: the view projected at the named frontier, the
/// ledger-local aliases, and the manifest judgments the dispatcher derived
/// over that view. Nothing here is a second source of truth.
pub struct ViewContext<'a> {
    pub view: &'a NormView,
    pub aliases: &'a BTreeMap<String, String>,
    pub manifests: &'a BTreeMap<String, ManifestJudgment>,
}

/// One admitted act as an explanation reads it: its causal parents and its
/// verified statement. Built by the dispatcher from the captured history.
#[derive(Clone, Debug)]
pub struct ExplainedAct {
    pub parents: Vec<String>,
    pub statement: NormStatement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordHead {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub vocabulary: VocabularyRef,
    pub revision: String,
    pub status: String,
    pub head: String,
}

fn head_of(context: &ViewContext<'_>, record: &NormRecord) -> RecordHead {
    RecordHead {
        id: record.id.clone(),
        alias: context.aliases.get(&record.id).cloned(),
        vocabulary: record.vocabulary.clone(),
        revision: record.content_head.clone(),
        status: record.status.clone(),
        head: record.head.clone(),
    }
}

fn frontier_of(view: &NormView) -> Vec<String> {
    view.frontier.iter().cloned().collect()
}

fn refused(message: impl Into<String>) -> StoreError {
    StoreError::Conflict(message.into())
}

fn record_at<'a>(view: &'a NormView, record: &str) -> StoreResult<&'a NormRecord> {
    view.records
        .get(record)
        .ok_or_else(|| refused("no norm record with that id at this frontier"))
}

// ---------------------------------------------------------------------------
// Rendering

/// A manifest as a readable document at one frontier: its own fields, its
/// members at their exact revisions in the order it lists them, and the
/// derived completeness judgment, kept apart from the members.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRendering {
    pub frontier: Vec<String>,
    pub manifest: RecordHead,
    /// The manifest's fields other than its member list, as declared.
    pub document: Value,
    /// Presentation order is the manifest's; order and grouping are not
    /// membership, and the count of what is listed here is not an inventory.
    pub members: Vec<RenderedMember>,
    /// The judgment derived at the basis the manifest bound, or bounded to
    /// its scope. Never inferred from `members`.
    pub completeness: ManifestJudgment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedMember {
    /// The revision reference the manifest names.
    pub reference: String,
    /// The record at exactly that revision, as it stood when admitted.
    pub record: RecordHead,
    pub fields: Value,
    /// How that revision stands at the rendering frontier.
    pub standing: MemberStanding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemberStanding {
    /// The named revision is the record's effective revision here.
    Effective,
    /// Another revision of the record is effective here.
    Superseded { effective: String },
    /// The record has no effective revision here.
    Inactive,
    /// The charter gives the record's vocabulary no effectiveness rule.
    Unspecified,
}

fn standing_of(view: &NormView, reference: &str, record: &NormRecord) -> MemberStanding {
    match view.effective_revision(record) {
        EffectiveRevision::Unspecified => MemberStanding::Unspecified,
        EffectiveRevision::Inactive => MemberStanding::Inactive,
        EffectiveRevision::Active { record, .. } if record.content_head == reference => {
            MemberStanding::Effective
        }
        EffectiveRevision::Active { record, .. } => MemberStanding::Superseded {
            effective: record.content_head.clone(),
        },
    }
}

fn manifest_members(record: &NormRecord, field: &str) -> Vec<String> {
    record
        .fields
        .get(field)
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Render one manifest at the context's frontier.
pub fn render_manifest(
    context: &ViewContext<'_>,
    manifest: &str,
) -> StoreResult<ManifestRendering> {
    let view = context.view;
    let record = record_at(view, manifest)?;
    let Some((_, declaration)) = view.manifest_of(&record.vocabulary) else {
        // MUTATION-SUCCESS-EXPR: Ok(ManifestRendering { frontier: Vec::new(), manifest: head_of(context, record), document: Value::Null, members: Vec::new(), completeness: context.manifests.values().next().cloned().unwrap() })
        return Err(refused(
            "the record is not a manifest under its charter entry",
        ));
    };
    let completeness = context
        .manifests
        .get(manifest)
        .cloned()
        .ok_or_else(|| refused("the manifest has no derived completeness judgment"))?;
    let mut members = Vec::new();
    for reference in manifest_members(record, &declaration.members) {
        // Members are causal parents of the manifest's act, so every one is
        // an admitted revision at any frontier that includes the manifest.
        let at_revision = view
            .revision(&reference)
            .ok_or_else(|| refused("manifest member does not resolve at this frontier"))?;
        let current = record_at(view, &at_revision.id)?;
        members.push(RenderedMember {
            reference: reference.clone(),
            record: head_of(context, at_revision),
            fields: at_revision.fields.clone(),
            standing: standing_of(view, &reference, current),
        });
    }
    let document = match &record.fields {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .filter(|(name, _)| *name != &declaration.members)
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        ),
        other => other.clone(),
    };
    Ok(ManifestRendering {
        frontier: frontier_of(view),
        manifest: head_of(context, record),
        document,
        members,
        completeness,
    })
}

// ---------------------------------------------------------------------------
// The diff of meaning

/// What changed between two named frontiers, over whole-record revisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeaningDiff {
    pub before: Vec<String>,
    pub after: Vec<String>,
    /// Whether each end's applicable inventory is completely classified, so
    /// an empty change set is never mistaken for a complete one.
    pub inventory: InventoryEnds,
    pub records: Vec<RecordChange>,
    pub edges: Vec<EdgeChange>,
    pub manifests: Vec<ManifestChange>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryEnds {
    pub before_classification_complete: bool,
    pub after_classification_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordChange {
    pub record: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub vocabulary: VocabularyRef,
    pub changes: Vec<RecordChangeKind>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordChangeKind {
    /// Absent at the before frontier, present at the after frontier.
    Created {
        revision: String,
    },
    /// Present at the before frontier, absent at the after frontier: the
    /// after frontier does not reach the record's creation.
    Unreached {
        revision: String,
    },
    /// The content revision moved; the classification is the declaration's.
    Revised {
        from: String,
        to: String,
        classification: ChangeClass,
        fields: Vec<FieldChange>,
    },
    Lifecycle {
        from: String,
        to: String,
    },
    Effect {
        from: EffectSummary,
        to: EffectSummary,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeClass {
    Meaning,
    Editorial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldChange {
    pub field: String,
    pub change: FieldChangeKind,
    pub classification: ChangeClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectSummary {
    Unspecified,
    Inactive,
    Active { revision: String, status: String },
}

fn effect_summary(view: &NormView, record: &NormRecord) -> EffectSummary {
    match view.effective_revision(record) {
        EffectiveRevision::Unspecified => EffectSummary::Unspecified,
        EffectiveRevision::Inactive => EffectSummary::Inactive,
        EffectiveRevision::Active { record, lifecycle } => EffectSummary::Active {
            revision: record.content_head.clone(),
            status: lifecycle.status,
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EdgeChange {
    Added { family: String, edge: RelationEdge },
    Withdrawn { family: String, edge: RelationEdge },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestChange {
    pub record: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub members_added: Vec<String>,
    pub members_removed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<ManifestJudgment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<ManifestJudgment>,
}

/// The declaration's classification of one field of one record's vocabulary.
fn classify(view: &NormView, vocabulary: &VocabularyRef, field: &str) -> ChangeClass {
    let editorial = view
        .charter
        .vocabularies
        .iter()
        .find(|entry| {
            entry.definition.name == vocabulary.name
                && entry.definition.version == vocabulary.version
        })
        .and_then(|entry| {
            entry
                .definition
                .fields
                .iter()
                .find(|declared| declared.name == field)
        })
        .is_some_and(|declared| declared.editorial);
    if editorial {
        ChangeClass::Editorial
    } else {
        ChangeClass::Meaning
    }
}

/// Field-by-field comparison of two revisions of one record, each change
/// classified by the declaration. The revision is editorial only when every
/// changed field is.
pub fn classify_revision(
    view: &NormView,
    vocabulary: &VocabularyRef,
    before: &Value,
    after: &Value,
) -> (ChangeClass, Vec<FieldChange>) {
    let empty = serde_json::Map::new();
    let before = before.as_object().unwrap_or(&empty);
    let after = after.as_object().unwrap_or(&empty);
    let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut fields = Vec::new();
    for name in names {
        let change = match (before.get(name), after.get(name)) {
            (None, Some(_)) => FieldChangeKind::Added,
            (Some(_), None) => FieldChangeKind::Removed,
            (Some(was), Some(is)) if was != is => FieldChangeKind::Changed,
            _ => continue,
        };
        fields.push(FieldChange {
            field: name.clone(),
            change,
            classification: classify(view, vocabulary, name),
        });
    }
    let classification = if !fields.is_empty()
        && fields
            .iter()
            .all(|field| field.classification == ChangeClass::Editorial)
    {
        ChangeClass::Editorial
    } else {
        ChangeClass::Meaning
    };
    (classification, fields)
}

/// The diff of meaning from `before` to `after`. Both are projections at
/// named frontiers of one history; neither need include the other.
pub fn diff_meaning(before: &ViewContext<'_>, after: &ViewContext<'_>) -> StoreResult<MeaningDiff> {
    let before_inventory = before.view.requirement_inventory()?;
    let after_inventory = after.view.requirement_inventory()?;
    let alias = |id: &str| {
        after
            .aliases
            .get(id)
            .or_else(|| before.aliases.get(id))
            .cloned()
    };
    let mut records = Vec::new();
    let ids: BTreeSet<&String> = before
        .view
        .records
        .keys()
        .chain(after.view.records.keys())
        .collect();
    for id in ids {
        let mut changes = Vec::new();
        let vocabulary;
        match (before.view.records.get(id), after.view.records.get(id)) {
            (None, Some(is)) => {
                vocabulary = is.vocabulary.clone();
                changes.push(RecordChangeKind::Created {
                    revision: is.content_head.clone(),
                });
            }
            (Some(was), None) => {
                vocabulary = was.vocabulary.clone();
                changes.push(RecordChangeKind::Unreached {
                    revision: was.content_head.clone(),
                });
            }
            (Some(was), Some(is)) => {
                vocabulary = is.vocabulary.clone();
                if was.content_head != is.content_head {
                    let (classification, fields) =
                        classify_revision(after.view, &is.vocabulary, &was.fields, &is.fields);
                    changes.push(RecordChangeKind::Revised {
                        from: was.content_head.clone(),
                        to: is.content_head.clone(),
                        classification,
                        fields,
                    });
                }
                if was.status != is.status {
                    changes.push(RecordChangeKind::Lifecycle {
                        from: was.status.clone(),
                        to: is.status.clone(),
                    });
                }
                let (from, to) = (
                    effect_summary(before.view, was),
                    effect_summary(after.view, is),
                );
                if from != to {
                    changes.push(RecordChangeKind::Effect { from, to });
                }
            }
            (None, None) => unreachable!("id came from one of the two views"),
        }
        if !changes.is_empty() {
            records.push(RecordChange {
                record: id.clone(),
                alias: alias(id),
                vocabulary,
                changes,
            });
        }
    }

    let before_families = before.view.relation_families()?;
    let after_families = after.view.relation_families()?;
    let mut edges = Vec::new();
    let families: BTreeSet<&String> = before_families
        .keys()
        .chain(after_families.keys())
        .collect();
    for family in families {
        let was: BTreeSet<&RelationEdge> = before_families
            .get(family)
            .map(|view| view.edges.iter().collect())
            .unwrap_or_default();
        let is: BTreeSet<&RelationEdge> = after_families
            .get(family)
            .map(|view| view.edges.iter().collect())
            .unwrap_or_default();
        for edge in was.difference(&is) {
            edges.push(EdgeChange::Withdrawn {
                family: family.clone(),
                edge: (*edge).clone(),
            });
        }
        for edge in is.difference(&was) {
            edges.push(EdgeChange::Added {
                family: family.clone(),
                edge: (*edge).clone(),
            });
        }
    }

    let mut manifests = Vec::new();
    let manifest_ids: BTreeSet<&String> = before
        .manifests
        .keys()
        .chain(after.manifests.keys())
        .collect();
    for id in manifest_ids {
        let members_at = |context: &ViewContext<'_>| -> BTreeSet<String> {
            context
                .view
                .records
                .get(id)
                .and_then(|record| {
                    context
                        .view
                        .manifest_of(&record.vocabulary)
                        .map(|(_, declaration)| manifest_members(record, &declaration.members))
                })
                .unwrap_or_default()
                .into_iter()
                .collect()
        };
        let (was, is) = (members_at(before), members_at(after));
        let before_judgment = before.manifests.get(id).cloned();
        let after_judgment = after.manifests.get(id).cloned();
        if was == is && before_judgment == after_judgment {
            continue;
        }
        manifests.push(ManifestChange {
            record: id.clone(),
            alias: alias(id),
            members_added: is.difference(&was).cloned().collect(),
            members_removed: was.difference(&is).cloned().collect(),
            before: before_judgment,
            after: after_judgment,
        });
    }

    Ok(MeaningDiff {
        before: frontier_of(before.view),
        after: frontier_of(after.view),
        inventory: InventoryEnds {
            before_classification_complete: before_inventory.classification_complete,
            after_classification_complete: after_inventory.classification_complete,
        },
        records,
        edges,
        manifests,
    })
}

// ---------------------------------------------------------------------------
// Explanation

/// Why one record stands as it does at a frontier. Every node is one of five
/// kinds and names the basis it was read at.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Explanation {
    pub frontier: Vec<String>,
    pub subject: RecordHead,
    pub nodes: Vec<ExplanationNode>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationNode {
    pub kind: ExplanationKind,
    pub basis: ExplanationBasis,
    pub statement: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub detail: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationKind {
    Obligation,
    Revision,
    Evidence,
    Premise,
    Authority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExplanationBasis {
    /// Read from the projected view at this frontier.
    Frontier { frontier: Vec<String> },
    /// Read from a relation family's live edges at the basis an act binds.
    Family { family: String, basis: String },
    /// Read from the applicable inventory judged at this frontier.
    Inventory { frontier: Vec<String> },
    /// Read from one admitted act.
    Act { event: String },
}

fn premises_detail(premises: &NormPremises) -> Value {
    serde_json::to_value(premises).unwrap_or(Value::Null)
}

fn admission_text(predicate: &AdmissionPredicate) -> String {
    match predicate {
        AdmissionPredicate::Public {} => "public admission".into(),
        AdmissionPredicate::Authority { scope } => format!("authority scope {scope}"),
    }
}

/// Explain one record at the context's frontier. `acts` carries every act
/// of the projected history the explanation may cite.
pub fn explain_record(
    context: &ViewContext<'_>,
    acts: &BTreeMap<String, ExplainedAct>,
    record: &str,
) -> StoreResult<Explanation> {
    let view = context.view;
    let subject = record_at(view, record)?;
    let frontier = frontier_of(view);
    let at_frontier = || ExplanationBasis::Frontier {
        frontier: frontier.clone(),
    };
    let mut nodes = Vec::new();

    // Revision: where the record stands, and which revision is effective.
    nodes.push(ExplanationNode {
        kind: ExplanationKind::Revision,
        basis: at_frontier(),
        statement: format!(
            "the record is at revision {} with status {}",
            subject.content_head, subject.status
        ),
        detail: serde_json::json!({
            "revision": subject.content_head,
            "status": subject.status,
            "head": subject.head,
            "revisions": view.revisions_of(record),
        }),
    });
    let effective = view.effective_revision(subject);
    match &effective {
        EffectiveRevision::Active { record: active, lifecycle } => {
            nodes.push(ExplanationNode {
                kind: ExplanationKind::Revision,
                basis: ExplanationBasis::Act {
                    event: lifecycle.head.clone(),
                },
                statement: format!(
                    "revision {} is effective with lifecycle status {}",
                    active.content_head, lifecycle.status
                ),
                detail: serde_json::json!({
                    "revision": active.content_head,
                    "status": lifecycle.status,
                    "activation": lifecycle.head,
                }),
            });
        }
        EffectiveRevision::Inactive => nodes.push(ExplanationNode {
            kind: ExplanationKind::Revision,
            basis: at_frontier(),
            statement: "no revision of the record is effective".into(),
            detail: Value::Null,
        }),
        EffectiveRevision::Unspecified => nodes.push(ExplanationNode {
            kind: ExplanationKind::Revision,
            basis: at_frontier(),
            statement: "effectiveness is unspecified: the charter gives this vocabulary no effectiveness rule".into(),
            detail: Value::Null,
        }),
    }

    // Authority: who created it, who activated it and under which rule, and
    // the authority epoch the view stands under.
    if let Some(creation) = acts.get(record) {
        nodes.push(ExplanationNode {
            kind: ExplanationKind::Authority,
            basis: ExplanationBasis::Act {
                event: record.to_owned(),
            },
            statement: format!("created by {}", creation.statement.actor.principal),
            detail: serde_json::json!({
                "principal": creation.statement.actor.principal,
                "key_id": creation.statement.actor.key_id,
                "created_at": creation.statement.created_at,
            }),
        });
    }
    if let EffectiveRevision::Active { lifecycle, .. } = &effective {
        let rules: Vec<Value> = view
            .charter
            .vocabularies
            .iter()
            .find(|entry| {
                entry.definition.name == subject.vocabulary.name
                    && entry.definition.version == subject.vocabulary.version
            })
            .map(|entry| {
                entry
                    .definition
                    .status
                    .transitions
                    .iter()
                    .filter(|rule| rule.to == lifecycle.status)
                    .map(|rule| {
                        serde_json::json!({
                            "from": rule.from,
                            "to": rule.to,
                            "admission": admission_text(&rule.admission),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let actor = acts
            .get(&lifecycle.head)
            .map(|act| act.statement.actor.principal.clone());
        nodes.push(ExplanationNode {
            kind: ExplanationKind::Authority,
            basis: ExplanationBasis::Act {
                event: lifecycle.head.clone(),
            },
            statement: match &actor {
                Some(actor) => format!(
                    "activated by {actor}; admission to {} is governed by the declared rules",
                    lifecycle.status
                ),
                None => format!(
                    "admission to {} is governed by the declared rules",
                    lifecycle.status
                ),
            },
            detail: serde_json::json!({ "actor": actor, "rules": rules }),
        });
    }
    nodes.push(ExplanationNode {
        kind: ExplanationKind::Authority,
        basis: at_frontier(),
        statement: format!(
            "the view stands under authority epoch {}",
            view.authority_head
        ),
        detail: serde_json::json!({ "authority": view.authority_head, "owner": view.owner.principal }),
    });

    // Premise: what the establishing acts bound.
    let mut cited = BTreeSet::new();
    for event in [subject.content_head.as_str(), subject.head.as_str()] {
        if !cited.insert(event.to_owned()) {
            continue;
        }
        let Some(act) = acts.get(event) else {
            continue;
        };
        nodes.push(ExplanationNode {
            kind: ExplanationKind::Premise,
            basis: ExplanationBasis::Act {
                event: event.to_owned(),
            },
            statement: match &act.statement.premises {
                Some(_) => "the act bound its premises as causal parents".into(),
                None => "the act bound no premises beyond its causal parents".into(),
            },
            detail: serde_json::json!({
                "parents": act.parents,
                "premises": act.statement.premises.as_ref().map(premises_detail),
            }),
        });
    }
    if let Some(basis) = view.manifest_basis(record) {
        nodes.push(ExplanationNode {
            kind: ExplanationKind::Premise,
            basis: ExplanationBasis::Inventory {
                frontier: basis.to_vec(),
            },
            statement: "the exhaustive claim was judged against the inventory at this frontier"
                .into(),
            detail: Value::Null,
        });
    }

    // Obligation: the record as an applicable requirement, or the
    // requirements the record's live edges name.
    let inventory = view.requirement_inventory()?;
    let inventory_basis = || ExplanationBasis::Inventory {
        frontier: inventory.frontier.iter().cloned().collect(),
    };
    if let Some(requirement) = inventory.requirements.get(record) {
        nodes.push(ExplanationNode {
            kind: ExplanationKind::Obligation,
            basis: inventory_basis(),
            statement: match &requirement.declaration {
                Some(declaration) => format!(
                    "applicable requirement {}: {}",
                    declaration.name, declaration.proposition
                ),
                None => "applicable requirement whose declaration is not interpretable".into(),
            },
            detail: serde_json::json!({
                "revision": requirement.source.content_head,
                "lifecycle": requirement.lifecycle,
                "declaration": requirement.declaration,
            }),
        });
    } else if inventory.inactive.contains(record)
        || inventory.unclassified.contains(record)
        || inventory.non_requirements.contains(record)
    {
        let classification = if inventory.inactive.contains(record) {
            "inactive"
        } else if inventory.unclassified.contains(record) {
            "unclassified"
        } else {
            "not a requirement"
        };
        nodes.push(ExplanationNode {
            kind: ExplanationKind::Obligation,
            basis: inventory_basis(),
            statement: format!("the record is {classification} in the applicable inventory"),
            detail: Value::Null,
        });
    }
    for gap in inventory
        .gaps
        .iter()
        .filter(|gap| gap.record.as_deref() == Some(record))
    {
        nodes.push(ExplanationNode {
            kind: ExplanationKind::Obligation,
            basis: inventory_basis(),
            statement: "the inventory records a classification gap for this record".into(),
            detail: serde_json::to_value(gap).unwrap_or(Value::Null),
        });
    }

    // Evidence: live edges the record is an endpoint of, the obligations
    // those edges name, the manifests that list its revisions, and its own
    // completeness judgment when it is a manifest.
    let revisions: BTreeSet<String> = view.revisions_of(record).into_iter().collect();
    for (family, family_view) in view.relation_families()? {
        for edge in &family_view.edges {
            if edge.source != record && edge.target != record {
                continue;
            }
            let edge_record = record_at(view, &edge.record)?;
            let references = view
                .relation_of(&edge_record.vocabulary)
                .map(|(_, declaration)| {
                    serde_json::json!({
                        "source": edge_record.fields.get(&declaration.source),
                        "target": edge_record.fields.get(&declaration.target),
                    })
                })
                .unwrap_or(Value::Null);
            let family_basis = || ExplanationBasis::Family {
                family: family.clone(),
                basis: family_view.basis.clone(),
            };
            nodes.push(ExplanationNode {
                kind: ExplanationKind::Evidence,
                basis: family_basis(),
                statement: format!(
                    "live {} edge from {} to {} (record {} at revision {})",
                    edge.relation, edge.source, edge.target, edge.record, edge.revision
                ),
                detail: serde_json::json!({ "edge": edge, "references": references }),
            });
            if edge.source == record {
                if let Some(requirement) = inventory.requirements.get(&edge.target) {
                    let named = references
                        .get("target")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let effective = requirement.source.content_head.clone();
                    let statement = match &named {
                        Some(named) if *named != effective => format!(
                            "{} names obligation {} at revision {named}; its effective revision here is {effective}",
                            edge.relation, edge.target
                        ),
                        _ => format!(
                            "{} names obligation {} at its effective revision {effective}",
                            edge.relation, edge.target
                        ),
                    };
                    nodes.push(ExplanationNode {
                        kind: ExplanationKind::Obligation,
                        basis: family_basis(),
                        statement,
                        detail: serde_json::json!({
                            "requirement": edge.target,
                            "named": named,
                            "effective": effective,
                            "declaration": requirement.declaration,
                        }),
                    });
                }
            }
        }
    }
    for (manifest_id, judgment) in context.manifests {
        if manifest_id == record {
            let (statement, basis) = match &judgment.completeness {
                ManifestCompleteness::Complete { basis } => (
                    "the exhaustive claim is complete at its basis".to_owned(),
                    ExplanationBasis::Inventory {
                        frontier: basis.clone(),
                    },
                ),
                ManifestCompleteness::Incomplete { basis, missing } => (
                    format!(
                        "the exhaustive claim is incomplete at its basis: {} applicable revision(s) missing",
                        missing.len()
                    ),
                    ExplanationBasis::Inventory {
                        frontier: basis.clone(),
                    },
                ),
                ManifestCompleteness::Unresolved { basis, reason } => (
                    format!("no total judgment exists: {reason}"),
                    ExplanationBasis::Inventory {
                        frontier: basis.clone(),
                    },
                ),
                ManifestCompleteness::Bounded { scope } => (
                    match scope {
                        Some(scope) => format!("the claim is bounded to scope {scope}; never total"),
                        None => "the claim is bounded; never total".to_owned(),
                    },
                    at_frontier(),
                ),
            };
            nodes.push(ExplanationNode {
                kind: ExplanationKind::Evidence,
                basis,
                statement,
                detail: serde_json::to_value(judgment).unwrap_or(Value::Null),
            });
            continue;
        }
        let Some(manifest) = view.records.get(manifest_id) else {
            continue;
        };
        let Some((_, declaration)) = view.manifest_of(&manifest.vocabulary) else {
            continue;
        };
        for member in manifest_members(manifest, &declaration.members) {
            if revisions.contains(&member) {
                nodes.push(ExplanationNode {
                    kind: ExplanationKind::Evidence,
                    basis: at_frontier(),
                    statement: format!(
                        "revision {member} is a member of manifest {manifest_id} at revision {}",
                        manifest.content_head
                    ),
                    detail: serde_json::json!({
                        "manifest": manifest_id,
                        "member": member,
                        "completeness": judgment.completeness,
                    }),
                });
            }
        }
    }

    Ok(Explanation {
        frontier,
        subject: head_of(context, subject),
        nodes,
    })
}
