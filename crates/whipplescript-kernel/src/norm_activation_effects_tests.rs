//! Running effects across a charter activation (norm-plane §10, slice W1):
//! the runtime store's running norm effects are planned into the migration,
//! a publication already prepared is never stranded, and a retired
//! requirement's late outcome is not published.
use super::*;
use crate::exec_http::sha256_hex;
use crate::norm_publication::{ObservationSigning, PreparedObservationPublication};
use std::collections::BTreeMap;
use whipplescript_core::vocabulary::{Vocabulary, VocabularyRef};
use whipplescript_store::norm::*;
use whipplescript_store::norm_activation::{
    LateOutcome, MigrationPlan, RunningEffectPlan, VocabularyMigration,
};
use whipplescript_store::norm_commands::{
    NormCommand, NormCommandHost, NormCommandRequest, NormCommandResult,
};
use whipplescript_store::norm_publication::{running_norm_effects, RunningNormEffect};
use whipplescript_store::SqliteStore;

use super::fixtures::*;

fn reference(entry: &NormVocabulary) -> VocabularyRef {
    Vocabulary::new(entry.definition.clone())
        .expect("a valid vocabulary")
        .reference()
        .clone()
}

/// The fixture's requirement vocabulary, `local-duty`.
fn duty(view: &NormView) -> NormVocabulary {
    view.charter
        .vocabularies
        .iter()
        .find(|entry| entry.definition.name == "local-duty")
        .expect("the fixture's requirement vocabulary")
        .clone()
}

/// A successor charter and its migration: every vocabulary with a live
/// record is retained, except the requirement's, which `plan` names.
fn proposal(view: &NormView, plan: &str) -> (NormCharter, Vec<VocabularyMigration>) {
    let old = duty(view);
    let mut charter = view.charter.clone();
    let duty_plan = match plan {
        "retain" => MigrationPlan::Retain {},
        "retire" => MigrationPlan::Retire {},
        _ => {
            let mut successor = old.clone();
            successor.definition.version = "2".into();
            let statuses: BTreeMap<String, String> = old
                .definition
                .status
                .values
                .iter()
                .map(|status| (status.clone(), status.clone()))
                .collect();
            let slot = charter
                .vocabularies
                .iter_mut()
                .find(|entry| entry.definition.name == "local-duty")
                .expect("the fixture's requirement vocabulary");
            *slot = successor.clone();
            MigrationPlan::Successor {
                vocabulary: reference(&successor),
                statuses,
            }
        }
    };
    let migration = view
        .charter
        .vocabularies
        .iter()
        .filter(|entry| {
            view.records
                .values()
                .any(|record| record.vocabulary == reference(entry) && view.record_is_live(record))
        })
        .map(|entry| VocabularyMigration {
            from: reference(entry),
            plan: if entry.definition.name == "local-duty" {
                duty_plan.clone()
            } else {
                MigrationPlan::Retain {}
            },
        })
        .collect();
    (charter, migration)
}

fn activation(view: &NormView, plan: &str) -> SignedNormEvent {
    let (charter, migration) = proposal(view, plan);
    sign(
        &format!("activate-{plan}"),
        NormAct::Activate {
            ledger: view.ledger.clone(),
            previous: view.authority_head.clone(),
            charter,
            migration,
            changes: Vec::new(),
            frontier: view.frontier.iter().cloned().collect(),
        },
    )
}

fn late_outcomes(plans: &[RunningEffectPlan]) -> Vec<(String, LateOutcome)> {
    plans
        .iter()
        .map(|plan| (plan.effect.effect.clone(), plan.late.clone()))
        .collect()
}

#[test]
fn an_activation_plans_every_running_norm_effect_and_never_strands_a_prepared_publication() {
    let (mut ledger, record) = fixture_with_observation(Some(template()), true, true);
    let captured = history(&ledger);
    let ledger_id = captured.anchor().checkpoint.ledger;
    let prepared = PreparedNormExecution::prepare(
        &captured,
        &Boundary,
        &artifact("def allow(user): return False"),
        &script(),
        selection(&ledger_id, &record),
    )
    .unwrap();
    let instance = "instance".to_owned();
    let kernel = journal_execution_as(
        SqliteStore::open_in_memory().unwrap(),
        &prepared,
        &receipt(&prepared, false, false),
        false,
        &instance,
        "run",
    );
    let runtime = kernel.store();

    // The settled run and its unstarted sibling are both running: neither
    // outcome has reached the ledger. Another ledger's are not listed.
    let running = running_norm_effects(runtime).unwrap();
    let effects: Vec<&str> = running
        .iter()
        .map(|effect| effect.effect.as_str())
        .collect();
    assert_eq!(effects, ["observe", "observe-foreign"]);
    assert!(running.iter().all(|effect| effect.ledger == ledger_id
        && effect.requirement == record
        && effect.prepared.is_none()));

    // Each migration of the requirement decides its runs' late outcomes.
    let view = ledger.norm_view(&Boundary).unwrap();
    let successor = reference(&{
        let mut next = duty(&view);
        next.definition.version = "2".into();
        next
    });
    for (plan, late) in [
        ("retain", LateOutcome::Kept {}),
        (
            "successor",
            LateOutcome::Pinned {
                successor: successor.clone(),
            },
        ),
        ("retire", LateOutcome::Retired {}),
    ] {
        let (charter, migration) = proposal(&view, plan);
        assert_eq!(
            view.activation_obstructions(&charter, &migration, &[])
                .unwrap(),
            Vec::new(),
            "{plan}"
        );
        let (plans, obstructions) = view.plan_running_effects(&migration, &running);
        assert!(obstructions.is_empty(), "{plan}");
        assert_eq!(
            late_outcomes(&plans),
            [
                ("observe".to_owned(), late.clone()),
                ("observe-foreign".to_owned(), late)
            ],
            "{plan}"
        );
    }
    // A run naming a requirement the ledger does not hold is located.
    let stray = RunningNormEffect {
        requirement: "no-such-record".into(),
        ..running[0].clone()
    };
    let (_, obstructions) =
        view.plan_running_effects(&proposal(&view, "retain").1, std::slice::from_ref(&stray));
    assert_eq!(obstructions[0].record.as_deref(), Some("no-such-record"));

    // A prepared publication names the epoch an activation closes and is
    // never signed again, so the activation that would strand it is refused:
    // planned first, and at the door, with nothing appended.
    let verified = prepared.verify_settled(runtime, &instance, "run").unwrap();
    let observation = reference(&observation_vocabulary());
    let actor = actor();
    let signing = || ObservationSigning {
        vocabulary: &observation,
        authority: None,
        actor: &actor,
        created_at: "2026-09-10T00:00:00Z",
    };
    let publication = PreparedObservationPublication::prepare(
        &verified,
        &captured,
        runtime,
        &Boundary,
        signing(),
        |statement| Ok(sha256_hex(&statement.signing_bytes().unwrap())),
    )
    .unwrap();
    let running = running_norm_effects(runtime).unwrap();
    assert_eq!(running[0].prepared.as_deref(), Some("run"));
    assert_eq!(running[1].prepared, None);
    let (charter, migration) = proposal(&view, "retain");
    let listed = || running_norm_effects(runtime);
    let planned = NormCommandHost::new(&mut ledger, &Boundary)
        .with_running_effects(&listed)
        .execute(NormCommandRequest::new(NormCommand::PlanActivation {
            proposal: Box::new(whipplescript_store::norm_activation::ActivationProposal {
                charter,
                migration,
                changes: Vec::new(),
            }),
        }))
        .unwrap();
    let NormCommandResult::ActivationPlanned {
        obstructions,
        effects,
        ..
    } = planned.result
    else {
        panic!("an activation plan")
    };
    assert_eq!(obstructions.len(), 1);
    assert_eq!(obstructions[0].record.as_deref(), Some(record.as_str()));
    assert_eq!(
        obstructions[0].rule.as_deref(),
        Some("effect observe run run")
    );
    assert!(obstructions[0].reason.contains("stranded"));
    assert_eq!(effects.unwrap().len(), 2);
    let head = view.authority_head.clone();
    let refused = NormCommandHost::new(&mut ledger, &Boundary)
        .with_running_effects(&listed)
        .execute(NormCommandRequest::new(NormCommand::append(activation(
            &view, "retain",
        ))))
        .expect_err("stranding activation");
    assert!(format!("{refused:?}").contains("stranded"), "{refused:?}");
    assert_eq!(ledger.norm_view(&Boundary).unwrap().authority_head, head);

    // Submitted and acknowledged, the outcome is no longer running, and the
    // activation retiring the requirement is admitted.
    publication
        .submit(&mut ledger, &Boundary)
        .unwrap()
        .acknowledge(runtime)
        .unwrap();
    let running = running_norm_effects(runtime).unwrap();
    assert_eq!(
        running
            .iter()
            .map(|effect| effect.effect.as_str())
            .collect::<Vec<_>>(),
        ["observe-foreign"]
    );
    let view = ledger.norm_view(&Boundary).unwrap();
    NormCommandHost::new(&mut ledger, &Boundary)
        .with_running_effects(&listed)
        .execute(NormCommandRequest::new(NormCommand::append(activation(
            &view, "retire",
        ))))
        .unwrap();
    let retired = ledger.norm_view(&Boundary).unwrap();
    assert!(retired.is_retired(&record));

    // A late outcome of the retired requirement is not published, and its
    // run stays in the runtime journal.
    let late = PreparedNormExecution::prepare(
        &captured,
        &Boundary,
        &artifact("def allow(user): return False"),
        &script(),
        NormRunSelection {
            effect_id: "observe-late",
            ..selection(&ledger_id, &record)
        },
    )
    .unwrap();
    let late_instance = "late-instance".to_owned();
    let late_kernel = journal_execution_as(
        SqliteStore::open_in_memory().unwrap(),
        &late,
        &receipt(&late, false, false),
        false,
        &late_instance,
        "late-run",
    );
    let late_verified = late
        .verify_settled(late_kernel.store(), &late_instance, "late-run")
        .unwrap();
    let before = late_kernel.store().list_events(&late_instance).unwrap();
    let refused = PreparedObservationPublication::prepare(
        &late_verified,
        &history(&ledger),
        late_kernel.store(),
        &Boundary,
        signing(),
        |_| panic!("a retired requirement's outcome is refused before signing"),
    )
    .expect_err("retired requirement");
    assert!(refused.contains("was retired"), "{refused}");
    assert!(PreparedObservationPublication::draft(
        &late_verified,
        &history(&ledger),
        late_kernel.store(),
        &Boundary,
        signing(),
    )
    .is_err());
    assert_eq!(
        late_kernel.store().list_events(&late_instance).unwrap(),
        before
    );
}

#[test]
fn a_late_outcome_under_a_successor_evidences_only_the_revision_it_was_pinned_to() {
    let (mut ledger, record) = fixture_with_observation(Some(template()), true, true);
    let captured = history(&ledger);
    let ledger_id = captured.anchor().checkpoint.ledger;
    let prepared = PreparedNormExecution::prepare(
        &captured,
        &Boundary,
        &artifact("def allow(user): return False"),
        &script(),
        selection(&ledger_id, &record),
    )
    .unwrap();
    let kernel = journal_execution_as(
        SqliteStore::open_in_memory().unwrap(),
        &prepared,
        &receipt(&prepared, false, false),
        false,
        "instance",
        "run",
    );
    let runtime = kernel.store();
    let view = ledger.norm_view(&Boundary).unwrap();
    let listed = || running_norm_effects(runtime);
    NormCommandHost::new(&mut ledger, &Boundary)
        .with_running_effects(&listed)
        .execute(NormCommandRequest::new(NormCommand::append(activation(
            &view,
            "successor",
        ))))
        .unwrap();

    // The requirement moved with its content, and a successor is a new
    // revision: the run's pinned identity is no longer the one in force.
    let after = ledger.norm_view(&Boundary).unwrap();
    assert_eq!(after.records[&record].vocabulary.version, "2");
    let current = after.requirement_inventory().unwrap().requirements[&record]
        .requirement
        .clone()
        .unwrap();
    assert_ne!(current, prepared.intent().requirement);

    // Its late outcome is still published, fresh under the new epoch, and
    // names the revision it evidences.
    let verified = prepared.verify_settled(runtime, "instance", "run").unwrap();
    let observation = reference(&observation_vocabulary());
    let actor = actor();
    let after_history = history(&ledger);
    let event = PreparedObservationPublication::prepare(
        &verified,
        &after_history,
        runtime,
        &Boundary,
        ObservationSigning {
            vocabulary: &observation,
            authority: Some(&after.authority_head),
            actor: &actor,
            created_at: "2026-09-10T00:00:00Z",
        },
        |statement| Ok(sha256_hex(&statement.signing_bytes().unwrap())),
    )
    .unwrap()
    .submit(&mut ledger, &Boundary)
    .unwrap();
    let published = ledger.norm_view(&Boundary).unwrap();
    let fields = &published
        .records
        .values()
        .find(|record| record.head == event.event_id())
        .unwrap()
        .fields;
    let invocation: NormRunIntent =
        serde_json::from_str(fields["invocation_json"].as_str().unwrap()).unwrap();
    assert_eq!(invocation.requirement, prepared.intent().requirement);
    assert_ne!(invocation.requirement, current);
}
