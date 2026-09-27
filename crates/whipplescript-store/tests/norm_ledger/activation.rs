// Charter activation (norm-plane §10, slice W1): the preceding charter's
// authority installs a successor, and its migration plans every live record.

use whipplescript_core::vocabulary::VocabularyRef;
use whipplescript_store::norm_activation::*;

fn vocabulary(value: serde_json::Value) -> NormVocabulary {
    serde_json::from_value(value).expect("vocabulary fixture")
}

fn reference(entry: &NormVocabulary) -> VocabularyRef {
    Vocabulary::new(entry.definition.clone())
        .expect("definition")
        .reference()
        .clone()
}

fn decision_v1() -> NormVocabulary {
    vocabulary(json!({
        "definition": {"name":"decision","version":"1",
            "fields":[{"name":"title","required":true,"value_type":{"type":"text"}}],
            "status":{"values":["proposed","accepted","retired","withdrawn"],"initial":"proposed","transitions":[
                {"from":"proposed","to":"accepted","admission":{"requires":"authority","scope":"accept"}},
                {"from":"accepted","to":"retired","admission":{"requires":"authority","scope":"accept"}},
                {"from":"proposed","to":"withdrawn","admission":{"requires":"public"}}]}},
        "creation":{"requires":"public"},
        "effectiveness":[{"status":"accepted","effect":"activate"},{"status":"retired","effect":"retire"}],
        "inventory_role":{"kind":"non_requirement"}
    }))
}

/// The successor decision: renamed statuses, an optional summary, and the
/// approving step under whatever admission the case needs.
fn decision_v2(approve: serde_json::Value, retiring: bool) -> NormVocabulary {
    let mut transitions = vec![
        json!({"from":"draft","to":"approved","admission":approve}),
        json!({"from":"draft","to":"withdrawn","admission":{"requires":"public"}}),
    ];
    if retiring {
        transitions.push(json!({"from":"approved","to":"retired","admission":{"requires":"authority","scope":"accept"}}));
    }
    vocabulary(json!({
        "definition": {"name":"decision","version":"2",
            "fields":[{"name":"title","required":true,"value_type":{"type":"text"}},
                      {"name":"summary","required":false,"value_type":{"type":"text"}}],
            "status":{"values":["draft","approved","retired","withdrawn"],"initial":"draft","transitions":transitions}},
        "creation":{"requires":"public"},
        "effectiveness":[{"status":"approved","effect":"activate"},{"status":"retired","effect":"retire"}],
        "inventory_role":{"kind":"non_requirement"}
    }))
}

fn note_v1() -> NormVocabulary {
    vocabulary(json!({
        "definition": {"name":"note","version":"1",
            "fields":[{"name":"text","required":true,"value_type":{"type":"text"}}],
            "status":{"values":["open","done"],"initial":"open","transitions":[
                {"from":"open","to":"done","admission":{"requires":"public"}}]}},
        "creation":{"requires":"public"},
        "inventory_role":{"kind":"non_requirement"}
    }))
}

fn duty(version: &str, requirement: bool) -> NormVocabulary {
    let role = if requirement {
        json!({"kind":"requirement","fields":{"name":"name","proposition":"proposition","domain":"domain","subject":"subject"}})
    } else {
        json!({"kind":"non_requirement"})
    };
    let fields: Vec<serde_json::Value> = ["name", "proposition", "domain", "subject"]
        .iter()
        .map(|name| json!({"name":name,"required":true,"value_type":{"type":"text"}}))
        .collect();
    vocabulary(json!({
        "definition": {"name":"duty","version":version,
            "fields":fields,
            "status":{"values":["proposed","accepted","retired"],"initial":"proposed","transitions":[
                {"from":"proposed","to":"accepted","admission":{"requires":"authority","scope":"accept"}},
                {"from":"accepted","to":"retired","admission":{"requires":"authority","scope":"accept"}}]}},
        "creation":{"requires":"public"},
        "effectiveness":[{"status":"accepted","effect":"activate"},{"status":"retired","effect":"retire"}],
        "inventory_role":role
    }))
}

fn governed(vocabularies: Vec<NormVocabulary>) -> NormCharter {
    NormCharter {
        resource_domains: None,
        vocabularies,
        owner_scopes: vec!["accept".into(), "activate".into()],
        activation: Some(AdmissionPredicate::Authority {
            scope: "activate".into(),
        }),
        gated_refs: vec![],
    }
}

fn statuses() -> BTreeMap<String, String> {
    [
        ("proposed", "draft"),
        ("accepted", "approved"),
        ("retired", "retired"),
        ("withdrawn", "withdrawn"),
    ]
    .into_iter()
    .map(|(from, to)| (from.to_owned(), to.to_owned()))
    .collect()
}

fn create(
    keys: &Keys,
    store: &mut WorkItemStore,
    entry: &NormVocabulary,
    fields: serde_json::Value,
    nonce: &str,
) -> String {
    let view = store.norm_view(keys).unwrap();
    let event = keys.sign(
        "worker",
        nonce,
        NormAct::Create {
            ledger: view.ledger.clone(),
            authority: Some(view.authority_head.clone()),
            vocabulary: reference(entry),
            fields_json: fields.to_string(),
        },
    );
    store.append_norm_event(&event, keys).unwrap()
}

fn transition(keys: &Keys, view: &NormView, actor: &str, record: &str, status: &str, nonce: &str) -> SignedNormEvent {
    let current = &view.records[record];
    keys.sign(
        actor,
        nonce,
        NormAct::Transition {
            ledger: view.ledger.clone(),
            authority: Some(view.authority_head.clone()),
            vocabulary: current.vocabulary.clone(),
            record: record.into(),
            previous: current.head.clone(),
            status: status.into(),
        },
    )
}

fn activation(
    keys: &Keys,
    view: &NormView,
    actor: &str,
    nonce: &str,
    charter: NormCharter,
    migration: Vec<VocabularyMigration>,
    changes: Vec<AuthorizedChange>,
) -> SignedNormEvent {
    keys.sign(
        actor,
        nonce,
        NormAct::Activate {
            ledger: view.ledger.clone(),
            previous: view.authority_head.clone(),
            charter,
            migration,
            changes,
            frontier: view.frontier.iter().cloned().collect(),
        },
    )
}

fn successor(from: &NormVocabulary, to: &NormVocabulary, map: BTreeMap<String, String>) -> VocabularyMigration {
    VocabularyMigration {
        from: reference(from),
        plan: MigrationPlan::Successor {
            vocabulary: reference(to),
            statuses: map,
        },
    }
}

fn plan(from: &NormVocabulary, plan: MigrationPlan) -> VocabularyMigration {
    VocabularyMigration {
        from: reference(from),
        plan,
    }
}

fn public_approval(to: &NormVocabulary) -> AuthorizedChange {
    AuthorizedChange {
        vocabulary: reference(to),
        rule: ChangedRule::Transition {
            from: "draft".into(),
            to: "approved".into(),
        },
        rationale: "any contributor approves a draft under the new charter".into(),
    }
}

struct Ledger {
    keys: Keys,
    store: WorkItemStore,
    proposed: String,
    accepted: String,
    withdrawn: String,
    note: String,
    duty: String,
}

/// One live proposed decision, one effective accepted decision, one closed
/// withdrawn decision, one live note and one effective requirement.
fn ledger() -> Ledger {
    let keys = Keys::new();
    let mut store = WorkItemStore::open_in_memory().unwrap();
    let genesis = keys.sign(
        "owner",
        "genesis",
        NormAct::Bootstrap {
            creator: "worker".into(),
            charter: governed(vec![decision_v1(), note_v1(), duty("1", true)]),
        },
    );
    store.append_norm_event(&genesis, &keys).unwrap();
    let title = |title: &str| json!({ "title": title });
    let proposed = create(&keys, &mut store, &decision_v1(), title("open question"), "proposed");
    let accepted = create(&keys, &mut store, &decision_v1(), title("settled"), "accepted");
    let withdrawn = create(&keys, &mut store, &decision_v1(), title("dropped"), "withdrawn");
    let note = create(&keys, &mut store, &note_v1(), json!({"text":"follow up"}), "note");
    let duty = create(
        &keys,
        &mut store,
        &duty("1", true),
        json!({"name":"deny unknown","proposition":"unknown callers are denied","domain":"src/","subject":"src/auth.py"}),
        "duty",
    );
    for (record, status, actor, nonce) in [
        (&accepted, "accepted", "owner", "accept"),
        (&withdrawn, "withdrawn", "worker", "withdraw"),
        (&duty, "accepted", "owner", "accept-duty"),
    ] {
        let view = store.norm_view(&keys).unwrap();
        let event = transition(&keys, &view, actor, record, status, nonce);
        store.append_norm_event(&event, &keys).unwrap();
    }
    Ledger {
        keys,
        store,
        proposed,
        accepted,
        withdrawn,
        note,
        duty,
    }
}

/// The admissible activation: decisions succeed, notes retire, duties stay.
fn complete(
    view: &NormView,
    keys: &Keys,
    nonce: &str,
    successor_decision: NormVocabulary,
    changes: Vec<AuthorizedChange>,
) -> SignedNormEvent {
    activation(
        keys,
        view,
        "owner",
        nonce,
        governed(vec![successor_decision.clone(), duty("1", true)]),
        vec![
            successor(&decision_v1(), &successor_decision, statuses()),
            plan(&note_v1(), MigrationPlan::Retire {}),
            plan(&duty("1", true), MigrationPlan::Retain {}),
        ],
        changes,
    )
}

fn refusal(store: &mut WorkItemStore, keys: &Keys, event: &SignedNormEvent) -> String {
    let before = store.export_events().unwrap();
    let error = store
        .append_norm_event(event, keys)
        .expect_err("the activation must be refused");
    assert_eq!(
        store.export_events().unwrap(),
        before,
        "a refused activation changes nothing"
    );
    format!("{error:?}")
}

#[test]
fn norm_charter_activation_refuses_with_every_obstruction_located() {
    let Ledger {
        keys,
        mut store,
        proposed,
        accepted,
        note,
        duty: requirement,
        ..
    } = ledger();
    let view = store.norm_view(&keys).unwrap();
    let strong = decision_v2(json!({"requires":"authority","scope":"accept"}), true);
    let weak = decision_v2(json!({"requires":"public"}), true);

    // Only the preceding charter's activation authority installs a charter.
    let error = refusal(
        &mut store,
        &keys,
        &activation(
            &keys,
            &view,
            "worker",
            "worker-activation",
            governed(vec![strong.clone(), duty("1", true)]),
            vec![],
            vec![],
        ),
    );
    assert!(error.contains("lacks the charter's authenticated governance authority"), "{error}");

    // A closed frontier is the exact one: an activation that leaves an act
    // out would let that act run under a charter it never saw.
    let mut stale = view.clone();
    stale.frontier.pop_first();
    let error = refusal(
        &mut store,
        &keys,
        &complete(&stale, &keys, "stale-frontier", strong.clone(), vec![]),
    );
    assert!(error.contains("exact current event frontier"), "{error}");

    // Every obstruction at once, each located: the note has no plan, and the
    // successor opens approval to anyone without saying so.
    let error = refusal(
        &mut store,
        &keys,
        &activation(
            &keys,
            &view,
            "owner",
            "unplanned-and-laundered",
            governed(vec![weak.clone(), duty("1", true)]),
            vec![
                successor(&decision_v1(), &weak, statuses()),
                plan(&duty("1", true), MigrationPlan::Retain {}),
            ],
            vec![],
        ),
    );
    assert!(error.contains("charter activation is obstructed:"), "{error}");
    assert!(error.contains(&format!("note@1 record {note}: a live record has no migration plan")), "{error}");
    assert!(error.contains("decision@1 rule draft -> approved: the successor weakens a step without a declared change"), "{error}");

    // What the record's status means for effectiveness is kept: mapping the
    // accepted decision onto a draft would silently withdraw it, and mapping
    // the proposed one onto an approval would resurrect nothing into force.
    let mut unfaithful = statuses();
    unfaithful.insert("accepted".into(), "draft".into());
    unfaithful.insert("proposed".into(), "approved".into());
    let error = refusal(
        &mut store,
        &keys,
        &activation(
            &keys,
            &view,
            "owner",
            "unfaithful-map",
            governed(vec![strong.clone(), duty("1", true)]),
            vec![
                successor(&decision_v1(), &strong, unfaithful),
                plan(&note_v1(), MigrationPlan::Retire {}),
                plan(&duty("1", true), MigrationPlan::Retain {}),
            ],
            vec![],
        ),
    );
    assert!(error.contains(&format!("decision@1 record {accepted}: accepted -> draft changes what the record's status means")), "{error}");
    assert!(error.contains(&format!("decision@1 record {proposed}: proposed -> approved changes what the record's status means")), "{error}");

    // A partial status map, a dropped step, a demoted requirement, a
    // retained vocabulary the new charter does not carry, and a declared
    // change the successor does not make.
    let mut partial = statuses();
    partial.remove("withdrawn");
    let unretiring = decision_v2(json!({"requires":"authority","scope":"accept"}), false);
    for (case, charter, migration, changes, expected) in [
        (
            "partial-map",
            governed(vec![strong.clone(), duty("1", true)]),
            vec![
                successor(&decision_v1(), &strong, partial),
                plan(&note_v1(), MigrationPlan::Retire {}),
                plan(&duty("1", true), MigrationPlan::Retain {}),
            ],
            vec![],
            "decision@1: the status map must name every status of the old vocabulary exactly once".to_owned(),
        ),
        (
            "dropped-step",
            governed(vec![unretiring.clone(), duty("1", true)]),
            vec![
                successor(&decision_v1(), &unretiring, statuses()),
                plan(&note_v1(), MigrationPlan::Retire {}),
                plan(&duty("1", true), MigrationPlan::Retain {}),
            ],
            vec![],
            "decision@1 rule approved -> retired: the successor drops the step accepted -> retired without a declared change".to_owned(),
        ),
        (
            "demoted",
            governed(vec![strong.clone(), duty("2", false)]),
            vec![
                successor(&decision_v1(), &strong, statuses()),
                plan(&note_v1(), MigrationPlan::Retire {}),
                successor(
                    &duty("1", true),
                    &duty("2", false),
                    [("proposed", "proposed"), ("accepted", "accepted"), ("retired", "retired")]
                        .into_iter()
                        .map(|(a, b)| (a.to_owned(), b.to_owned()))
                        .collect(),
                ),
            ],
            vec![],
            "duty@1: a successor would demote a live requirement out of the inventory".to_owned(),
        ),
        (
            "retained-missing",
            governed(vec![strong.clone()]),
            vec![
                successor(&decision_v1(), &strong, statuses()),
                plan(&note_v1(), MigrationPlan::Retire {}),
                plan(&duty("1", true), MigrationPlan::Retain {}),
            ],
            vec![],
            "duty@1: a retained vocabulary must be carried unchanged by the new charter".to_owned(),
        ),
        (
            "idle-declaration",
            governed(vec![strong.clone(), duty("1", true)]),
            vec![
                successor(&decision_v1(), &strong, statuses()),
                plan(&note_v1(), MigrationPlan::Retire {}),
                plan(&duty("1", true), MigrationPlan::Retain {}),
            ],
            vec![public_approval(&strong)],
            "decision@2 rule draft -> approved: a declared change is not a change this activation makes".to_owned(),
        ),
    ] {
        let error = refusal(
            &mut store,
            &keys,
            &activation(&keys, &view, "owner", case, charter, migration, changes),
        );
        assert!(error.contains(&expected), "{case}: {error}");
    }

    // A version is immutable, and an activation rule belongs to an authority.
    let mut redefined = note_v1();
    redefined.definition.fields[0].required = false;
    let error = refusal(
        &mut store,
        &keys,
        &activation(
            &keys,
            &view,
            "owner",
            "redefined",
            governed(vec![strong.clone(), duty("1", true), redefined]),
            vec![],
            vec![],
        ),
    );
    assert!(error.contains("redefines note@1; a new definition needs a new version"), "{error}");
    let mut open = governed(vec![strong.clone(), duty("1", true)]);
    open.activation = Some(AdmissionPredicate::Public {});
    let error = refusal(
        &mut store,
        &keys,
        &activation(&keys, &view, "owner", "public-activation", open, vec![], vec![]),
    );
    assert!(error.contains("charter activation must require one of the charter's own authority scopes"), "{error}");

    // A malformed proposal is refused outright rather than obstructed.
    let complete_plan = || {
        vec![
            successor(&decision_v1(), &strong, statuses()),
            plan(&note_v1(), MigrationPlan::Retire {}),
            plan(&duty("1", true), MigrationPlan::Retain {}),
        ]
    };
    let mut twice = complete_plan();
    twice.push(plan(&decision_v1(), MigrationPlan::Retire {}));
    let mut not_in_force = complete_plan();
    not_in_force.push(plan(&strong, MigrationPlan::Retain {}));
    let mut unexplained = public_approval(&strong);
    unexplained.rationale = " ".into();
    for (case, migration, changes, expected) in [
        ("planned-twice", twice, vec![], "the migration plans decision@1 twice"),
        (
            "not-in-force",
            not_in_force,
            vec![],
            "the migration plans decision@2, which is not in force",
        ),
        (
            "unexplained",
            complete_plan(),
            vec![unexplained],
            "a declared change needs a rationale",
        ),
        (
            "repeated",
            complete_plan(),
            vec![public_approval(&strong), public_approval(&strong)],
            "a declared change is repeated",
        ),
    ] {
        let error = refusal(
            &mut store,
            &keys,
            &activation(
                &keys,
                &view,
                "owner",
                case,
                governed(vec![strong.clone(), duty("1", true)]),
                migration,
                changes,
            ),
        );
        assert!(error.contains(expected), "{case}: {error}");
    }

    // Gated refs name distinct stream lines, and a gate is never released: a
    // successor that drops a line the charter in force gates is obstructed.
    for gated in [vec!["main".to_owned()], vec!["release".to_owned(), "release".to_owned()]] {
        let mut charter = governed(vec![strong.clone(), duty("1", true)]);
        charter.gated_refs = gated;
        let error = refusal(
            &mut store,
            &keys,
            &activation(&keys, &view, "owner", "bad-gates", charter, complete_plan(), vec![]),
        );
        assert!(
            error.contains("gated refs name distinct stream lines; the mainline is always gated"),
            "{error}"
        );
    }
    let mut gating = view.clone();
    gating.charter.gated_refs = vec!["release".into()];
    let released = gating
        .activation_obstructions(
            &governed(vec![strong.clone(), duty("1", true)]),
            &complete_plan(),
            &[],
        )
        .unwrap();
    assert_eq!(
        released,
        vec![ActivationObstruction {
            vocabulary: "charter".into(),
            record: None,
            rule: Some("gated ref release".into()),
            reason: "a successor charter releases a gated line; a gate is never released".into(),
        }]
    );

    // The same view lists what a refused activation would be told.
    let obstructions = view
        .activation_obstructions(
            &governed(vec![strong.clone(), duty("1", true)]),
            &[successor(&decision_v1(), &strong, statuses())],
            &[],
        )
        .unwrap();
    assert_eq!(
        obstructions,
        vec![
            ActivationObstruction {
                vocabulary: "duty@1".into(),
                record: Some(requirement.clone()),
                rule: None,
                reason: "a live record has no migration plan".into(),
            },
            ActivationObstruction {
                vocabulary: "note@1".into(),
                record: Some(note.clone()),
                rule: None,
                reason: "a live record has no migration plan".into(),
            },
        ]
    );

    // A charter that declares no activation rule is never replaced, whatever
    // its proposed successor would allow.
    let mut fixed = WorkItemStore::open_in_memory().unwrap();
    fixed.append_norm_event(&keys.bootstrap(), &keys).unwrap();
    let fixed_view = fixed.norm_view(&keys).unwrap();
    let error = refusal(
        &mut fixed,
        &keys,
        &activation(&keys, &fixed_view, "owner", "self-granted", governed(vec![]), vec![], vec![]),
    );
    assert!(error.contains("the charter in force declares no activation rule"), "{error}");
}

#[test]
fn norm_charter_activation_migrates_live_records_and_keeps_history_replayable() {
    let Ledger {
        keys,
        mut store,
        proposed,
        accepted,
        withdrawn,
        note,
        duty: requirement,
    } = ledger();
    let before = store.norm_view(&keys).unwrap();
    let weak = decision_v2(json!({"requires":"public"}), true);
    let event = complete(&before, &keys, "activate", weak.clone(), vec![public_approval(&weak)]);
    let activated = store.append_norm_event(&event, &keys).unwrap();
    assert_eq!(store.append_norm_event(&event, &keys).unwrap(), activated);
    let view = store.norm_view(&keys).unwrap();

    // The successor charter is in force, and it began an authority epoch that
    // the checkpoint records.
    assert_eq!(view.charter, governed(vec![weak.clone(), duty("1", true)]));
    assert_eq!(view.authority_head, activated);
    assert_eq!(store.norm_checkpoint().unwrap(), Some(view.checkpoint()));

    // Live decisions moved to the successor with their meaning intact.
    for (record, status) in [(&proposed, "draft"), (&accepted, "approved")] {
        let migrated = &view.records[record];
        assert_eq!(migrated.vocabulary, reference(&weak));
        assert_eq!(migrated.status, status);
        assert_eq!(migrated.head, activated);
        assert_eq!(migrated.fields, before.records[record].fields);
        assert_eq!(migrated.content_head, before.records[record].content_head);
    }
    let EffectiveRevision::Active { record, lifecycle } =
        view.effective_revision(&view.records[&accepted])
    else {
        panic!("the accepted decision stays effective");
    };
    assert_eq!(record.vocabulary, reference(&weak));
    assert_eq!(lifecycle.status, "approved");
    assert_eq!(lifecycle.head, before.effective_records[&accepted].head);

    // The closed decision keeps its original vocabulary, which still
    // interprets it though it is no longer in force.
    assert_eq!(view.records[&withdrawn], before.records[&withdrawn]);
    assert_eq!(view.interpretation(&reference(&decision_v1())), Some(&decision_v1()));
    assert_eq!(
        view.effective_revision(&view.records[&withdrawn]),
        EffectiveRevision::Inactive
    );
    // The requirement kept its vocabulary, its effectiveness and its place in
    // the inventory; the note was retired under the preceding authority.
    assert_eq!(view.records[&requirement], before.records[&requirement]);
    let inventory = view.requirement_inventory().unwrap();
    assert!(inventory.requirements.contains_key(&requirement));
    assert!(inventory.classification_complete);
    assert!(view.is_retired(&note));
    assert!(!view.is_retired(&proposed));

    // No act is admitted on a retired record or under a vocabulary no longer
    // in force, and none at the epoch the activation closed.
    let error = store
        .append_norm_event(&transition(&keys, &view, "worker", &note, "done", "late-note"), &keys)
        .unwrap_err();
    let error = format!("{error:?}");
    assert!(error.contains("retired by a charter activation"), "{error}");
    let old = keys.sign(
        "worker",
        "old-vocabulary",
        NormAct::Create {
            ledger: view.ledger.clone(),
            authority: Some(view.authority_head.clone()),
            vocabulary: reference(&decision_v1()),
            fields_json: json!({"title":"too late"}).to_string(),
        },
    );
    assert!(store.append_norm_event(&old, &keys).is_err());
    let error = store
        .append_norm_event(
            &transition(&keys, &view, "owner", &withdrawn, "proposed", "reopen-closed"),
            &keys,
        )
        .unwrap_err();
    let error = format!("{error:?}");
    assert!(error.contains("no longer in force; its history is read-only"), "{error}");
    let old_epoch = transition(&keys, &before, "owner", &proposed, "accepted", "old-epoch");
    assert!(store.append_norm_event(&old_epoch, &keys).is_err());

    // The declared change is what the preceding authority authorized: under
    // the successor anyone approves a draft.
    let approve = transition(&keys, &view, "worker", &proposed, "approved", "public-approval");
    store.append_norm_event(&approve, &keys).unwrap();
    let after = store.norm_view(&keys).unwrap();
    assert_eq!(after.records[&proposed].status, "approved");
    assert!(after.effective_records.contains_key(&proposed));

    // Replay is the same in any transport order, and a partial import that
    // drops the activation cannot fall back to the charter it replaced.
    let mut events = store.export_events().unwrap();
    let checkpoint = store.norm_checkpoint().unwrap().unwrap();
    events.reverse();
    let mut pinned = WorkItemStore::open_in_memory().unwrap();
    pinned.pin_norm_checkpoint(&checkpoint).unwrap();
    let partial: Vec<_> = events
        .iter()
        .filter(|event| event.event_id != activated)
        .filter(|event| {
            !event
                .parents
                .iter()
                .any(|parent| parent == &activated)
        })
        .cloned()
        .collect();
    assert!(pinned.import_norm_events(&partial, &keys).is_err());
    assert!(pinned.export_events().unwrap().is_empty());
    pinned.import_norm_events(&events, &keys).unwrap();
    let replayed = pinned.norm_view(&keys).unwrap();
    assert_eq!(replayed.records, after.records);
    assert_eq!(replayed.charter, after.charter);
    assert_eq!(pinned.norm_checkpoint().unwrap(), Some(checkpoint));

    // An act at the old epoch arriving after the activation is refused
    // whichever order a replay would apply it in.
    for before_activation in [true, false] {
        let concurrent = (0..1024)
            .map(|n| {
                keys.sign(
                    "worker",
                    &format!("concurrent-{n}"),
                    NormAct::Create {
                        ledger: before.ledger.clone(),
                        authority: Some(before.authority_head.clone()),
                        vocabulary: reference(&note_v1()),
                        fields_json: json!({"text":"concurrent"}).to_string(),
                    },
                )
            })
            .find(|event| (event.tracker_event().unwrap().event_id < activated) == before_activation)
            .unwrap();
        let original = store.export_events().unwrap();
        assert!(store
            .import_norm_events(&[concurrent.tracker_event().unwrap()], &keys)
            .is_err());
        assert_eq!(store.export_events().unwrap(), original);
    }
}
