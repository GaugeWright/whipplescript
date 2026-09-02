//! The instance view model: what a running instance is doing, and what it is
//! not.
//!
//! This is the projection `spec/instance-view-model-research-note.md` opened.
//! It joins the STATIC structure of the program version an instance is running
//! — recovered from the `.ir` snapshot the version stores under its own
//! `ir_hash` — to the RUNTIME state of that instance, and emits the nodes,
//! statuses and reasons a renderer needs.
//!
//! Two properties decide the shape.
//!
//! **The join is by identity, not inference.** A runtime effect id is a hash of
//! parts that include the snapshot's own node name, so this predicts ids FORWARD
//! and matches, rather than trying to invert a hash or guess from `kind`.
//!
//! **The log cannot represent absence.** A firing that takes one `case` arm
//! records nothing at all for the others, so from the log an arm never requested
//! and an arm that does not exist are the same observation. Only the static side
//! knows the others were there to not happen — which is why `absent` exists and
//! why it is the one thing this view offers over `whip log`.
//!
//! **No payload bytes cross this boundary.** Identifiers, statuses, reasons and
//! spans only: no fact values, no effect input, no turn output. A projection
//! that emitted them would make every consumer an egress and push the leak
//! decision onto whoever writes the UI. That is a property of this module, not a
//! flag on a renderer.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use whipplescript_kernel::idempotency_key;
use whipplescript_parser::snapshot;
use whipplescript_store::{EffectView, EventView, InstanceView, RunView};

pub const INSTANCE_VIEW_SCHEMA: &str = "whipplescript.instance_view.v0";

/// One advance of a firing: a `rule.committed` event, with the parts the effect
/// key is built from.
struct Commit {
    sequence: i64,
    occurred_at: String,
    rule: String,
    identity: String,
    program_version_id: String,
    revision_epoch: i64,
    /// The effect ids this commit actually created, straight from the payload.
    created: Vec<String>,
}

fn commits_from_events(events: &[EventView]) -> Vec<Commit> {
    events
        .iter()
        .filter(|event| event.event_type == "rule.committed")
        .filter_map(|event| {
            let payload: Value = serde_json::from_str(&event.payload_json).ok()?;
            let rule = payload.get("rule")?.as_str()?.to_owned();
            // A firing is its `context.identity`, NOT this event: one firing
            // emits a commit per `after` continuation, all sharing the identity.
            // A view keyed on the event would show one work item as several.
            let identity = payload
                .get("context")
                .and_then(|context| context.get("identity"))
                .and_then(Value::as_str)
                .unwrap_or("started")
                .to_owned();
            let created = payload
                .get("effects")
                .and_then(Value::as_array)
                .map(|effects| {
                    effects
                        .iter()
                        .filter_map(|effect| Some(effect.get("effect_id")?.as_str()?.to_owned()))
                        .collect()
                })
                .unwrap_or_default();
            Some(Commit {
                sequence: event.sequence,
                occurred_at: event.occurred_at.clone(),
                rule,
                identity,
                program_version_id: payload
                    .get("program_version_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                revision_epoch: payload
                    .get("revision_epoch")
                    .and_then(Value::as_i64)
                    .unwrap_or_default(),
                created,
            })
        })
        .collect()
}

/// The id a static node WOULD have in this firing, in the kernel's two forms
/// (`rule_lowering.rs:1503` and `:1734`). A root effect keys on its node; one
/// inside an `after` also keys on that arm's binding and predicate, which is
/// what DR-0090 put in the snapshot.
fn predicted_effect_id(
    instance_id: &str,
    program_version_id: &str,
    epoch_key: &str,
    rule: &str,
    node: &snapshot::SnapshotEffect,
    identity: &str,
) -> String {
    match &node.arm {
        Some((binding, predicate)) => idempotency_key(&[
            instance_id,
            program_version_id,
            epoch_key,
            rule,
            binding,
            predicate,
            &node.id,
            identity,
        ]),
        None => idempotency_key(&[
            instance_id,
            program_version_id,
            epoch_key,
            rule,
            &node.id,
            identity,
        ]),
    }
}

fn runs_for<'a>(runs: &'a [RunView], effect_id: &str) -> Vec<&'a RunView> {
    runs.iter()
        .filter(|run| run.effect_id == effect_id)
        .collect()
}

/// One program version's stored structure: the `ir_hash` the version carries,
/// and the `.ir` that hash names when the store holds it.
#[derive(Clone, Debug, Default)]
pub struct VersionSnapshot {
    pub ir_hash: String,
    pub snapshot: Option<String>,
}

/// Project one instance into the view model.
///
/// `versions` is keyed by `program_version_id`, and a firing is drawn against
/// ITS OWN version rather than the instance's current one. A revision moves a
/// live instance between program versions, so its effects can belong to two
/// different static graphs (the note's G3); drawing an older firing against the
/// newer structure would predict ids from the wrong nodes and report absences
/// that are artefacts of the revision.
///
/// Without a version's snapshot, structure — and therefore absence — is not
/// recoverable for its firings, and the view says so rather than presenting a
/// runtime-only picture as if it were whole.
pub fn project(
    instance: &InstanceView,
    versions: &BTreeMap<String, VersionSnapshot>,
    events: &[EventView],
    effects: &[EffectView],
    runs: &[RunView],
) -> Value {
    let parsed: BTreeMap<&str, snapshot::SnapshotView> = versions
        .iter()
        .filter_map(|(version_id, version)| {
            Some((
                version_id.as_str(),
                snapshot::parse(version.snapshot.as_ref()?),
            ))
        })
        .collect();
    let current = versions.get(&instance.version_id);
    let structure = parsed.get(instance.version_id.as_str());
    let by_id: BTreeMap<&str, &EffectView> = effects
        .iter()
        .map(|effect| (effect.effect_id.as_str(), effect))
        .collect();
    let commits = commits_from_events(events);

    // Group commits into firings. Order of first appearance is the order a
    // reader saw the work start, which is more useful than sorting by identity.
    let mut order: Vec<(String, String)> = Vec::new();
    let mut grouped: BTreeMap<(String, String), Vec<&Commit>> = BTreeMap::new();
    for commit in &commits {
        let key = (commit.rule.clone(), commit.identity.clone());
        if !grouped.contains_key(&key) {
            order.push(key.clone());
        }
        grouped.entry(key).or_default().push(commit);
    }

    let mut firings = Vec::new();
    let mut absent_total = 0usize;
    let mut attributed: BTreeSet<String> = BTreeSet::new();

    for key in &order {
        let group = &grouped[key];
        let (rule, identity) = key;
        let first = group[0];
        // G3: this firing's OWN version, not the instance's current one.
        let firing_structure = parsed.get(first.program_version_id.as_str());
        let mut slots = Vec::new();
        if let Some(view) = firing_structure.and_then(|view| view.rule(rule)) {
            for node in &view.effects {
                // The epoch key for an unbranched, never-restored instance is
                // the bare epoch (`rule_pass::revision_branch_key`). A branched
                // or restored one keys differently; `unattributed` below is what
                // makes that visible instead of silently reading as absent.
                let epoch_key = first.revision_epoch.to_string();
                let predicted = predicted_effect_id(
                    &instance.instance_id,
                    &first.program_version_id,
                    &epoch_key,
                    rule,
                    node,
                    identity,
                );
                let present = by_id.get(predicted.as_str());
                if present.is_some() {
                    attributed.insert(predicted.clone());
                }
                if present.is_none() {
                    absent_total += 1;
                }
                let mut slot = Map::new();
                slot.insert("node".to_owned(), json!(node.id));
                slot.insert("kind".to_owned(), json!(node.kind));
                slot.insert("binding".to_owned(), json!(node.binding));
                slot.insert(
                    "arm".to_owned(),
                    match &node.arm {
                        Some((binding, predicate)) => json!(format!("{binding}:{predicate}")),
                        None => Value::Null,
                    },
                );
                match present {
                    Some(effect) => {
                        slot.insert("effect_id".to_owned(), json!(effect.effect_id));
                        slot.insert("status".to_owned(), json!(effect.status));
                        slot.insert("block_reason".to_owned(), json!(effect.policy_block_reason));
                        slot.insert(
                            "block_category".to_owned(),
                            json!(effect.policy_block_category),
                        );
                        slot.insert(
                            "runs".to_owned(),
                            Value::Array(
                                runs_for(runs, &effect.effect_id)
                                    .into_iter()
                                    .map(|run| {
                                        json!({
                                            "run_id": run.run_id,
                                            "provider": run.provider,
                                            "worker_id": run.worker_id,
                                            "status": run.status,
                                            "started_at": run.started_at,
                                            "completed_at": run.completed_at,
                                        })
                                    })
                                    .collect::<Vec<_>>(),
                            ),
                        );
                    }
                    None => {
                        // The ghost. `absent` is not a status the runtime has —
                        // there is no row — which is exactly the point.
                        slot.insert("absent".to_owned(), json!(true));
                        slot.insert("predicted_effect_id".to_owned(), json!(predicted));
                    }
                }
                slots.push(Value::Object(slot));
            }
        }

        firings.push(json!({
            "rule": rule,
            "identity": identity,
            "commits": group.iter().map(|commit| json!({
                "sequence": commit.sequence,
                "occurred_at": commit.occurred_at,
            })).collect::<Vec<_>>(),
            "program_version_id": first.program_version_id,
            "revision_epoch": first.revision_epoch,
            // Stated per firing: a revision means the answer differs BETWEEN
            // firings of one instance, so one flag at the top would be wrong.
            "structure_available": firing_structure.is_some(),
            "effects": slots,
        }));
    }

    // Every program version the firings actually belong to, in order. More than
    // one means the instance was revised mid-flight.
    let mut versions_seen: Vec<String> = Vec::new();
    for commit in &commits {
        if !versions_seen.contains(&commit.program_version_id) {
            versions_seen.push(commit.program_version_id.clone());
        }
    }

    // Self-check. Every effect a commit reported creating should have been
    // attributed to a static node by prediction. One that was not means the
    // prediction is keyed differently than the run was — a branched or restored
    // instance, or a program version this snapshot does not describe — and the
    // absences above cannot be trusted. Saying so is the difference between an
    // incomplete picture and a confidently wrong one.
    let unattributed: Vec<&str> = commits
        .iter()
        .flat_map(|commit| commit.created.iter().map(String::as_str))
        .filter(|effect_id| !attributed.contains(*effect_id))
        .collect();

    json!({
        "schema": INSTANCE_VIEW_SCHEMA,
        "instance": {
            "instance_id": instance.instance_id,
            "status": instance.status,
            "program_version_id": instance.version_id,
            "revision_epoch": instance.revision_epoch,
            "ir_hash": current.map(|version| version.ir_hash.clone()).unwrap_or_default(),
        },
        // G3, said out loud: this instance was revised while running, so its
        // firings do not all belong to one program. A reader that assumed one
        // structure would be reading some of them against the wrong graph.
        "program_versions_seen": versions_seen,
        "structure": match structure {
            Some(view) => json!({
                "available": true,
                "program_version_id": instance.version_id,
                "ir_hash": current.map(|version| version.ir_hash.clone()).unwrap_or_default(),
                "workflow": view.workflow,
                "rules": view.rules.iter().map(|rule| json!({
                    "name": rule.name,
                    "whens": rule.whens,
                    "effects": rule.effects.iter().map(|effect| json!({
                        "node": effect.id,
                        "kind": effect.kind,
                        "binding": effect.binding,
                    })).collect::<Vec<_>>(),
                    "dependencies": rule.dependencies.iter().map(|(upstream, predicate, downstream)| json!({
                        "upstream": upstream,
                        "predicate": predicate,
                        "downstream": downstream,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "rule_edges": view.rule_dependencies.iter().map(|(producer, fact, consumer)| json!({
                    "producer": producer,
                    "fact": fact,
                    "consumer": consumer,
                })).collect::<Vec<_>>(),
            }),
            // Honest rather than empty: the structure is missing, so absence is
            // not computable and the firings below carry no slots.
            None => json!({
                "available": false,
                "program_version_id": instance.version_id,
                "reason": "no .ir snapshot is stored under this version's ir_hash",
            }),
        },
        "firings": firings,
        "absent_total": absent_total,
        "unattributed_effects": unattributed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(entries: &[(&str, Option<&str>)]) -> BTreeMap<String, VersionSnapshot> {
        entries
            .iter()
            .map(|(version_id, snapshot)| {
                (
                    (*version_id).to_owned(),
                    VersionSnapshot {
                        ir_hash: format!("ir-{version_id}"),
                        snapshot: snapshot.map(str::to_owned),
                    },
                )
            })
            .collect()
    }

    fn instance() -> InstanceView {
        InstanceView {
            instance_id: "ins_1".to_owned(),
            program_id: "prg_1".to_owned(),
            version_id: "ver_1".to_owned(),
            revision_epoch: 0,
            workflow_principal: String::new(),
            effective_authority_json: "[]".to_owned(),
            status: "running".to_owned(),
            input_json: "{}".to_owned(),
            created_at: "t0".to_owned(),
            updated_at: "t0".to_owned(),
        }
    }

    const SNAPSHOT: &str = "workflow Demo\n\
        rules\n  \
        rule work\n    \
        when started\n    \
        effects\n      \
        first kind=exec.command binding=first key=k1\n      \
        second kind=exec.command binding=second key=k2 arm=first:succeeds\n";

    fn commit_event(identity: &str, created: &[&str]) -> EventView {
        EventView {
            event_id: "evt_1".to_owned(),
            sequence: 1,
            event_type: "rule.committed".to_owned(),
            payload_json: json!({
                "rule": "work",
                "context": {"identity": identity},
                "program_version_id": "ver_1",
                "revision_epoch": 0,
                "effects": created.iter().map(|id| json!({"effect_id": id})).collect::<Vec<_>>(),
            })
            .to_string(),
            source: "kernel".to_owned(),
            occurred_at: "t1".to_owned(),
        }
    }

    fn effect(effect_id: &str, status: &str) -> EffectView {
        EffectView {
            effect_id: effect_id.to_owned(),
            kind: "exec.command".to_owned(),
            target: None,
            input_json: "{}".to_owned(),
            status: status.to_owned(),
            created_by_rule: "work".to_owned(),
            program_version_id: Some("ver_1".to_owned()),
            revision_epoch: 0,
            profile: None,
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
            policy_block_reason: None,
            policy_block_category: None,
            cancel_requested: false,
        }
    }

    fn id_for(node: &str, arm: Option<(&str, &str)>, identity: &str) -> String {
        match arm {
            Some((binding, predicate)) => idempotency_key(&[
                "ins_1", "ver_1", "0", "work", binding, predicate, node, identity,
            ]),
            None => idempotency_key(&["ins_1", "ver_1", "0", "work", node, identity]),
        }
    }

    /// The whole reason this view exists: a static node with no runtime row is
    /// reported as absent, distinctly from one that ran. A log cannot say this,
    /// because a path never requested leaves no record to read.
    #[test]
    fn a_node_with_no_runtime_row_is_absent_not_missing() {
        let first = id_for("first", None, "id-1");
        let view = project(
            &instance(),
            &versions(&[("ver_1", Some(SNAPSHOT))]),
            &[commit_event("id-1", &[&first])],
            &[effect(&first, "completed")],
            &[],
        );

        let slots = view["firings"][0]["effects"].as_array().expect("slots");
        assert_eq!(slots.len(), 2, "both static nodes are present in the view");
        assert_eq!(slots[0]["node"], "first");
        assert_eq!(slots[0]["status"], "completed");
        assert_eq!(slots[0]["absent"], Value::Null);

        assert_eq!(slots[1]["node"], "second");
        assert_eq!(slots[1]["absent"], true, "the arm that never ran");
        assert_eq!(slots[1]["arm"], "first:succeeds");
        assert_eq!(view["absent_total"], 1);
    }

    /// A continuation effect is matched through the arm DR-0090 put in the
    /// snapshot. Keyed without it, this effect would predict an id nothing
    /// produced and read as absent while plainly having run.
    #[test]
    fn a_continuation_effect_is_matched_through_its_arm() {
        let first = id_for("first", None, "id-1");
        let second = id_for("second", Some(("first", "succeeds")), "id-1");
        let view = project(
            &instance(),
            &versions(&[("ver_1", Some(SNAPSHOT))]),
            &[commit_event("id-1", &[&first, &second])],
            &[effect(&first, "completed"), effect(&second, "running")],
            &[],
        );

        let slots = view["firings"][0]["effects"].as_array().expect("slots");
        assert_eq!(slots[1]["status"], "running");
        assert_eq!(view["absent_total"], 0);
        assert_eq!(view["unattributed_effects"].as_array().unwrap().len(), 0);
    }

    /// One firing, many commits. `implement_ready_ticket` emits a
    /// `rule.committed` per `after` continuation, all sharing one identity, so a
    /// view keyed on the event would show one work item as several.
    #[test]
    fn commits_sharing_an_identity_are_one_firing() {
        let first = id_for("first", None, "id-1");
        let second = id_for("second", Some(("first", "succeeds")), "id-1");
        let mut later = commit_event("id-1", &[&second]);
        later.sequence = 7;

        let view = project(
            &instance(),
            &versions(&[("ver_1", Some(SNAPSHOT))]),
            &[commit_event("id-1", &[&first]), later],
            &[effect(&first, "completed"), effect(&second, "queued")],
            &[],
        );

        let firings = view["firings"].as_array().expect("firings");
        assert_eq!(firings.len(), 1, "two commits, one firing");
        assert_eq!(firings[0]["commits"].as_array().unwrap().len(), 2);
    }

    /// Two identities of the same rule are two firings, which is the divergence
    /// a rule-level roll-up hides.
    #[test]
    fn separate_identities_are_separate_firings() {
        let a = id_for("first", None, "id-1");
        let b = id_for("first", None, "id-2");
        let view = project(
            &instance(),
            &versions(&[("ver_1", Some(SNAPSHOT))]),
            &[commit_event("id-1", &[&a]), commit_event("id-2", &[&b])],
            &[effect(&a, "completed"), effect(&b, "blocked_by_capacity")],
            &[],
        );

        let firings = view["firings"].as_array().expect("firings");
        assert_eq!(firings.len(), 2);
        assert_eq!(firings[0]["effects"][0]["status"], "completed");
        assert_eq!(firings[1]["effects"][0]["status"], "blocked_by_capacity");
    }

    /// The self-check. An effect a commit reported creating that no prediction
    /// claims means this view is keyed differently than the run was — a branched
    /// or restored instance — and the absences cannot be trusted. Reporting it
    /// is the difference between an incomplete picture and a confident lie.
    #[test]
    fn an_effect_no_prediction_claims_is_reported_not_ignored() {
        let view = project(
            &instance(),
            &versions(&[("ver_1", Some(SNAPSHOT))]),
            &[commit_event("id-1", &["key_from_another_keying"])],
            &[effect("key_from_another_keying", "completed")],
            &[],
        );

        assert_eq!(
            view["unattributed_effects"],
            json!(["key_from_another_keying"]),
            "an unexplained effect is surfaced rather than silently leaving absences wrong"
        );
    }

    /// Without the snapshot there is no structure, so absence is not computable.
    /// The view says that rather than presenting a runtime-only picture as whole.
    #[test]
    fn a_missing_snapshot_is_stated_not_silently_empty() {
        let view = project(
            &instance(),
            &versions(&[("ver_1", None)]),
            &[commit_event("id-1", &[])],
            &[],
            &[],
        );

        assert_eq!(view["structure"]["available"], false);
        assert!(view["structure"]["reason"].as_str().is_some());
        assert_eq!(view["absent_total"], 0);
        assert_eq!(
            view["firings"][0]["effects"].as_array().unwrap().len(),
            0,
            "no slots are invented from a structure that was not recovered"
        );
    }

    /// G3: a revision moves a live instance between program versions, so one
    /// instance's firings can belong to two different static graphs. Each is
    /// drawn against ITS OWN version — drawing the older one against the newer
    /// structure would predict ids from nodes it never had and report absences
    /// that are artefacts of the revision, not of the run.
    #[test]
    fn a_revised_instance_draws_each_firing_against_its_own_version() {
        // v2 renamed the second node, so the two versions disagree about what
        // this rule contains.
        const V2: &str = "workflow Demo\n\
            rules\n  \
            rule work\n    \
            when started\n    \
            effects\n      \
            first kind=exec.command binding=first key=k1\n      \
            renamed kind=exec.command binding=renamed key=k9 arm=first:succeeds\n";

        let old_first = id_for("first", None, "id-1");
        let mut new_commit = commit_event("id-2", &[]);
        new_commit.sequence = 9;
        new_commit.payload_json = new_commit.payload_json.replace("\"ver_1\"", "\"ver_2\"");

        let mut current = instance();
        current.version_id = "ver_2".to_owned();

        let view = project(
            &current,
            &versions(&[("ver_1", Some(SNAPSHOT)), ("ver_2", Some(V2))]),
            &[commit_event("id-1", &[&old_first]), new_commit],
            &[effect(&old_first, "completed")],
            &[],
        );

        assert_eq!(
            view["program_versions_seen"],
            json!(["ver_1", "ver_2"]),
            "the split is stated, not hidden behind one structure"
        );
        let firings = view["firings"].as_array().expect("firings");
        // The old firing keeps the node its own version had...
        assert_eq!(firings[0]["program_version_id"], "ver_1");
        assert_eq!(firings[0]["effects"][1]["node"], "second");
        // ...and the new one gets the renamed node, from v2.
        assert_eq!(firings[1]["program_version_id"], "ver_2");
        assert_eq!(firings[1]["effects"][1]["node"], "renamed");
    }

    /// A version whose snapshot the store does not hold makes absence
    /// uncomputable for ITS firings only. Said per firing, because after a
    /// revision the answer genuinely differs between them.
    #[test]
    fn a_firing_whose_version_has_no_snapshot_says_so_for_itself() {
        let first = id_for("first", None, "id-1");
        let mut unknown = commit_event("id-2", &[]);
        unknown.payload_json = unknown.payload_json.replace("\"ver_1\"", "\"ver_gone\"");

        let view = project(
            &instance(),
            &versions(&[("ver_1", Some(SNAPSHOT))]),
            &[commit_event("id-1", &[&first]), unknown],
            &[effect(&first, "completed")],
            &[],
        );

        let firings = view["firings"].as_array().expect("firings");
        assert_eq!(firings[0]["structure_available"], true);
        assert_eq!(firings[1]["structure_available"], false);
        assert_eq!(firings[1]["effects"].as_array().unwrap().len(), 0);
    }

    /// The payload boundary, as a property of the projection rather than a
    /// renderer's setting: no fact value, effect input or turn output crosses.
    #[test]
    fn no_payload_bytes_cross_the_boundary() {
        let first = id_for("first", None, "id-1");
        let mut carrying = effect(&first, "completed");
        carrying.input_json = r#"{"secret":"hunter2"}"#.to_owned();

        let view = project(
            &instance(),
            &versions(&[("ver_1", Some(SNAPSHOT))]),
            &[commit_event("id-1", &[&first])],
            &[carrying],
            &[],
        );

        let rendered = view.to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("input_json"), "{rendered}");
    }
}
