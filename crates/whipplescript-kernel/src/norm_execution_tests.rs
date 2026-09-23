use super::*;
use crate::exec_http::sha256_hex;
use crate::norm_runner::PythonEngine;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_store::norm::*;

use super::fixtures::*;

#[test]
fn preparation_late_binds_verified_history_and_distinct_captures() {
    let (store, record) = fixture(Some(template()), true);
    let history = history(&store);
    let ledger = history.anchor().checkpoint.ledger;
    let mut prepared = Vec::new();
    for body in [
        "def allow(user): return False",
        "def allow(user): return True",
    ] {
        let artifact = artifact(body);
        let run = PreparedNormExecution::prepare(
            &history,
            &Boundary,
            &artifact,
            &script(),
            selection(&ledger, &record),
        )
        .unwrap();
        assert_eq!(run.intent().artifact, *artifact.basis());
        assert_eq!(
            run.intent().requirement,
            store
                .norm_view(&Boundary)
                .unwrap()
                .requirement_inventory()
                .unwrap()
                .requirements[&record]
                .requirement
                .clone()
                .unwrap()
        );
        assert_eq!(run.request().body["effect_id"], "observe");
        assert_eq!(run.effect_input()["stdin"], run.request().body["stdin"]);
        assert_eq!(run.effect_input()["norm_intent"], json!(run.intent()));
        let contract: ReportContract = serde_json::from_str(
            run.request().body["stdin"]["contract_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            contract.subject.artifact,
            candidate_identity(artifact.files())
        );
        assert_eq!(contract.cases[0].expected, json!(false));
        prepared.push(run);
    }
    assert_eq!(
        prepared[0].intent().requirement,
        prepared[1].intent().requirement
    );
    assert_ne!(prepared[0].request().body, prepared[1].request().body);
}
#[test]
fn preparation_refuses_inactive_missing_or_unsupported_support() {
    for (template, accepted, expected) in [
        (Some(template()), false, "active requirement"),
        (None, true, "no support template"),
        (
            Some(json!({"protocol":"unknown"})),
            true,
            "invalid norm support template",
        ),
        (
            Some(
                json!({"protocol":"whipplescript.norm.python-calls-support/v1","method":method(),"cases":[],"requirement":"self-reference"}),
            ),
            true,
            "invalid norm support template",
        ),
    ] {
        let (store, record) = fixture(template, accepted);
        let history = history(&store);
        let ledger = history.anchor().checkpoint.ledger;
        let err = PreparedNormExecution::prepare(
            &history,
            &Boundary,
            &artifact("def allow(user): return False"),
            &script(),
            selection(&ledger, &record),
        )
        .unwrap_err();
        assert!(err.contains(expected), "{err}");
    }
}
#[test]
fn preparation_refuses_foreign_selection_and_changed_installation() {
    let (store, record) = fixture(Some(template()), true);
    let history = history(&store);
    let ledger = history.anchor().checkpoint.ledger;
    let artifact = artifact("def allow(user): return False");
    for case in 0..11 {
        let mut selected = selection(&ledger, &record);
        let mut installed = script();
        match case {
            0 => selected.ledger = "foreign",
            1 => selected.publisher = " ",
            2 => installed.name.clear(),
            3 => selected.environment_epoch = "new epoch",
            4 => installed.hermetic = true,
            5 => installed.body.push(' '),
            6 => installed.sha256 = "wrong".into(),
            7 => installed.argv_json = json!(["python3", "{script}"]).to_string(),
            8 => installed.env_json = json!({"PYTHONPATH":"env:FOREIGN"}).to_string(),
            9 => selected.requirement = "missing",
            10 => selected.effect_id = "",
            _ => unreachable!(),
        }
        assert!(
            PreparedNormExecution::prepare(&history, &Boundary, &artifact, &installed, selected)
                .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn preparation_can_reconstruct_a_retired_requirements_captured_frontier() {
    let (mut store, record) = fixture(Some(template()), true);
    let old = store.norm_view(&Boundary).unwrap();
    let frontier: Vec<_> = old.frontier.iter().cloned().collect();
    let current = &old.records[&record];
    let active = &old.effective_records[&record];
    store
        .append_norm_event(
            &sign(
                "retire",
                NormAct::Retire {
                    ledger: old.ledger.clone(),
                    authority: Some(old.authority_head.clone()),
                    vocabulary: current.vocabulary.clone(),
                    record: record.clone(),
                    previous: current.head.clone(),
                    revision: active.content_head.clone(),
                    activation: active.head.clone(),
                    status: "retired".into(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let history = history(&store);
    let artifact = artifact("def allow(user): return False");
    assert!(PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &artifact,
        &script(),
        selection(&old.ledger, &record)
    )
    .unwrap_err()
    .contains("active requirement"));
    let mut selected = selection(&old.ledger, &record);
    selected.frontier = Some(&frontier);
    let prepared =
        PreparedNormExecution::prepare(&history, &Boundary, &artifact, &script(), selected)
            .unwrap();
    assert_eq!(prepared.intent().anchor.frontier, old.frontier);
    assert_ne!(prepared.intent().anchor.frontier, history.anchor().frontier);
    assert_eq!(
        prepared.intent().requirement,
        old.requirement_inventory().unwrap().requirements[&record]
            .requirement
            .clone()
            .unwrap()
    );
    let unknown = vec!["unknown".into()];
    let mut selected = selection(&old.ledger, &record);
    selected.frontier = Some(&unknown);
    assert!(
        PreparedNormExecution::prepare(&history, &Boundary, &artifact, &script(), selected)
            .is_err()
    );
}

#[test]
fn preparation_validates_complete_cases_and_installation_codecs() {
    let mut missing = template();
    missing["cases"] = json!([]);
    let (store, record) = fixture(Some(missing), true);
    let history = history(&store);
    let ledger = history.anchor().checkpoint.ledger;
    let captured = artifact("def allow(user): return False");
    assert!(PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &captured,
        &script(),
        selection(&ledger, &record)
    )
    .unwrap_err()
    .contains("complete unique contract inventory"));
    let (store, record) = fixture(Some(template()), true);
    let history = crate::norm_execution::tests::history(&store);
    let ledger = history.anchor().checkpoint.ledger;
    for field in ["argv", "env"] {
        let mut installed = script();
        if field == "argv" {
            installed.argv_json = "{}".into();
        } else {
            installed.env_json = "[]".into();
        }
        assert!(PreparedNormExecution::prepare(
            &history,
            &Boundary,
            &captured,
            &installed,
            selection(&ledger, &record)
        )
        .is_err());
    }
    assert!(PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &artifact("# module still exists"),
        &script(),
        selection(&ledger, &record)
    )
    .is_ok());
    // Entry-point callability is observed at execution, not guessed from source.
}

#[test]
fn preparation_and_reconstruction_pin_the_protected_observer_profile() {
    let mut protected = method();
    protected.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/runtime/python.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    protected.runtime.executable = "whip".into();
    let support = PythonCallSupport::V1 {
        method: protected.clone(),
        cases: vec![RequiredCase {
            id: "deny".into(),
            assertion: "unknown denied".into(),
            expected: json!(false),
        }],
    };
    let wire = serde_json::to_value(&support).unwrap();
    assert_eq!(
        serde_json::from_value::<PythonCallSupport>(wire.clone()).unwrap(),
        support
    );
    let (store, record) = fixture(Some(wire), true);
    let history = history(&store);
    let ledger = history.anchor().checkpoint.ledger;
    let mut installed = script();
    installed.body = protected.adapter().into();
    installed.sha256 = sha256_hex(installed.body.as_bytes());
    installed.argv_json = json!(["whip", "executor", "observe-norm", "{script}"]).to_string();
    let run = PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &artifact("def allow(user): return False"),
        &installed,
        selection(&ledger, &record),
    )
    .unwrap();
    assert_eq!(
        run.request().body["argv"],
        json!(["whip", "executor", "observe-norm", "{script}"])
    );
    let contract: ReportContract = serde_json::from_str(
        run.request().body["stdin"]["contract_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(contract.subject.method, protected.reference());
    assert!(run.effect_input().get("judgment").is_none());
    let captured = artifact("def allow(user): return False");
    let kernel = journal_execution(
        whipplescript_store::SqliteStore::open_in_memory().unwrap(),
        &run,
        &receipt(&run, false, false),
        false,
    );
    let recovered = PreparedNormExecution::recover_settled(
        &history,
        &Boundary,
        &captured,
        kernel.store(),
        "instance",
        "run",
    )
    .unwrap();
    assert_eq!(
        recovered.observation().observation_integrity,
        ObserverIntegrity::ProtectedInterpreter {}
    );
    use crate::norm_execution_policy::ProtectedPythonPolicy;
    use crate::norm_projection::ExecutionSelectionPolicy;
    let policy = ProtectedPythonPolicy::new(
        &serde_json::to_string(&protected.runtime).unwrap(),
        "captured",
    )
    .unwrap();
    let query = whipplescript_core::norm_selection::SelectionQuery {
        requirement: recovered.contract().subject.requirement.clone(),
        artifact: recovered.contract().subject.artifact.clone(),
        policy: policy.identity().clone(),
        time_basis: policy.time_basis().into(),
        frontier: recovered.intent().anchor.frontier.clone(),
    };
    assert!(policy.accepts(&query, &recovered));
    // Isolate defensive policy predicates using private fixture mutation. No
    // production constructor can upgrade or relabel a recovered execution.
    let mut altered = recovered.clone();
    altered.observation.observation_integrity = ObserverIntegrity::Cooperative {};
    assert!(!policy.accepts(&query, &altered));
    altered = recovered.clone();
    altered.contract.subject.method.digest.push('x');
    assert!(!policy.accepts(&query, &altered));
}

#[test]
fn preparation_blob_fixture_conforms() {
    whipplescript_store::content::conformance::run_suite(Blobs::default).unwrap();
}

#[test]
fn preparation_keeps_distinct_requirements_with_the_same_support_template() {
    let (mut store, first) = fixture(Some(template()), true);
    let view = store.norm_view(&Boundary).unwrap();
    let original = &view.records[&first];
    let second = store
        .append_norm_event(
            &sign(
                "second",
                NormAct::Create {
                    ledger: view.ledger.clone(),
                    authority: Some(view.authority_head.clone()),
                    vocabulary: original.vocabulary.clone(),
                    fields_json: json!(original.fields).to_string(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    store
        .append_norm_event(
            &sign(
                "accept-second",
                NormAct::Transition {
                    ledger: view.ledger.clone(),
                    authority: Some(view.authority_head.clone()),
                    vocabulary: original.vocabulary.clone(),
                    record: second.clone(),
                    previous: second.clone(),
                    status: "accepted".into(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let history = history(&store);
    let artifact = artifact("def allow(user): return False");
    let first = PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &artifact,
        &script(),
        selection(&view.ledger, &first),
    )
    .unwrap();
    let second = PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &artifact,
        &script(),
        selection(&view.ledger, &second),
    )
    .unwrap();
    assert_ne!(first.intent().requirement, second.intent().requirement);
    let contract = |run: &PreparedNormExecution| -> ReportContract {
        serde_json::from_str(
            run.request().body["stdin"]["contract_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(contract(&first).cases, contract(&second).cases);
    assert_ne!(
        contract(&first).subject.requirement,
        contract(&second).subject.requirement
    );
}

#[test]
fn preparation_refuses_active_records_without_usable_requirement_meaning() {
    let (mut store, record) = fixture(Some(template()), true);
    let view = store.norm_view(&Boundary).unwrap();
    let current = &view.records[&record];
    let mut fields = current.fields.clone();
    fields["proposition"] = json!(" ");
    let edit = store
        .append_norm_event(
            &sign(
                "blank-meaning",
                NormAct::Edit {
                    ledger: view.ledger.clone(),
                    authority: Some(view.authority_head.clone()),
                    vocabulary: current.vocabulary.clone(),
                    record: record.clone(),
                    previous: current.head.clone(),
                    fields_json: json!(fields).to_string(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    store
        .append_norm_event(
            &sign(
                "accept-blank",
                NormAct::Transition {
                    ledger: view.ledger.clone(),
                    authority: Some(view.authority_head.clone()),
                    vocabulary: current.vocabulary.clone(),
                    record: record.clone(),
                    previous: edit,
                    status: "accepted".into(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let history = history(&store);
    assert!(PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &artifact("def allow(user): return False"),
        &script(),
        selection(&view.ledger, &record)
    )
    .unwrap_err()
    .contains("no usable identity"));
}

#[test]
fn recovery_rebuilds_pass_fail_and_retained_harness_counterexamples_from_disk() {
    use whipplescript_core::norm_evidence::TestOutcome;
    use whipplescript_store::SqliteStore;
    for (actual, timeout, outcome, counters) in [
        (false, false, TestOutcome::Pass, 0),
        (true, false, TestOutcome::Fail, 1),
        (true, true, TestOutcome::HarnessFailed, 1),
    ] {
        let prepared = prepared_fixture();
        let path = std::env::temp_dir().join(format!(
            "norm-recovery-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let kernel = journal_execution(
            SqliteStore::open(&path).unwrap(),
            &prepared,
            &receipt(&prepared, actual, timeout),
            timeout || actual,
        );
        drop(kernel);
        let expected_intent = prepared.intent().clone();
        drop(prepared);
        // Reconstruct independently from history/capture after dropping the
        // execution host and preparation. No script registration is present.
        let (ledger, _) = fixture(Some(template()), true);
        let history = history(&ledger);
        let captured = artifact("def allow(user): return False");
        let mut store = SqliteStore::open(&path).unwrap();
        for rebuild in [false, true] {
            if rebuild {
                store.rebuild_projections("instance").unwrap();
            }
            let recovered = PreparedNormExecution::recover_settled(
                &history, &Boundary, &captured, &store, "instance", "run",
            )
            .unwrap();
            assert_eq!(recovered.observation().judgment.outcome, outcome);
            assert_eq!(
                recovered.observation().judgment.counterexamples.len(),
                counters
            );
            assert_eq!(recovered.intent(), &expected_intent);
            assert_eq!(recovered.instance_id(), "instance");
            assert_eq!(recovered.run_id(), "run");
            assert!(store.get_script_capability("observer").unwrap().is_none());
        }
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn recovery_refuses_missing_or_unbound_receipts() {
    for case in 0..3 {
        let prepared = prepared_fixture();
        let mut response = receipt(&prepared, false, false);
        match case {
            0 => response.body["effect_id"] = json!("other"),
            1 => response.body["stdout"] = json!(""),
            2 => response.status = 503,
            _ => unreachable!(),
        }
        let kernel = journal_execution(
            whipplescript_store::SqliteStore::open_in_memory().unwrap(),
            &prepared,
            &response,
            false,
        );
        let error = prepared
            .verify_settled(kernel.store(), "instance", "run")
            .unwrap_err();
        let expected = [
            "prepared invocation",
            "no bound observer header",
            "HTTP 503",
        ][case];
        assert!(error.contains(expected), "case {case}: {error}");
        assert!(prepared
            .verify_settled(kernel.store(), "other", "run")
            .is_err());
        assert!(prepared
            .verify_settled(kernel.store(), "instance", "missing")
            .is_err());
    }
}

#[test]
fn recovery_refuses_changed_journal_bindings_and_ignores_stored_judgment_labels() {
    use whipplescript_store::SqliteStore;
    let prepared = prepared_fixture();
    let path = std::env::temp_dir().join(format!(
        "norm-recovery-controls-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    drop(journal_execution(
        SqliteStore::open(&path).unwrap(),
        &prepared,
        &receipt(&prepared, true, false),
        true,
    ));
    let store = SqliteStore::open(&path).unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    let metadata = store.list_runs("instance").unwrap()[0]
        .metadata_json
        .clone();
    let completed_at = store.list_runs("instance").unwrap()[0].completed_at.clone();
    let original: Value = serde_json::from_str(&metadata).unwrap();
    for (field, value) in [
        ("protocol", json!("other")),
        ("capability", json!("other")),
        ("script_sha256", json!("other")),
        ("input_sha256", json!("other")),
        ("request_body_sha256", json!("other")),
        ("environment_epoch", json!("other")),
        ("content_key", json!("cache")),
        ("parse_contract", json!({"schema":"json"})),
    ] {
        let mut changed = original.clone();
        changed["executor_dispatch"][field] = value;
        sql.execute(
            "UPDATE runs SET metadata_json = ?1 WHERE run_id = 'run'",
            [changed.to_string()],
        )
        .unwrap();
        assert!(
            prepared.verify_settled(&store, "instance", "run").is_err(),
            "plan {field}"
        );
    }
    for field in ["executor_dispatch", "executor_response"] {
        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove(field);
        sql.execute(
            "UPDATE runs SET metadata_json = ?1 WHERE run_id = 'run'",
            [changed.to_string()],
        )
        .unwrap();
        assert!(
            prepared.verify_settled(&store, "instance", "run").is_err(),
            "missing {field}"
        );
    }
    sql.execute(
        "UPDATE runs SET metadata_json = ?1 WHERE run_id = 'run'",
        [&metadata],
    )
    .unwrap();
    for (query, value, restore) in [
        (
            "UPDATE effects SET kind = ?1 WHERE effect_id = 'observe'",
            "provider",
            "exec.command",
        ),
        (
            "UPDATE effects SET input_json = ?1 WHERE effect_id = 'observe'",
            "{}",
            prepared.effect_input().to_string().as_str(),
        ),
        (
            "UPDATE runs SET effect_id = ?1 WHERE run_id = 'run'",
            "foreign",
            "observe",
        ),
        (
            "UPDATE runs SET provider = ?1 WHERE run_id = 'run'",
            "other",
            "exec",
        ),
        (
            "UPDATE runs SET worker_id = ?1 WHERE run_id = 'run'",
            "other",
            "whip-exec",
        ),
        (
            "UPDATE runs SET status = ?1 WHERE run_id = 'run'",
            "running",
            "failed",
        ),
    ] {
        sql.execute(query, [value]).unwrap();
        assert!(
            prepared.verify_settled(&store, "instance", "run").is_err(),
            "{query}"
        );
        sql.execute(query, [restore]).unwrap();
    }
    sql.execute(
        "UPDATE runs SET completed_at = NULL WHERE run_id = 'run'",
        [],
    )
    .unwrap();
    assert!(prepared.verify_settled(&store, "instance", "run").is_err());
    sql.execute(
        "UPDATE runs SET completed_at = ?1 WHERE run_id = 'run'",
        [completed_at],
    )
    .unwrap();
    let mut labeled = original;
    labeled["judgment"] = json!({"outcome":"pass"});
    labeled["observation_integrity"] = json!({"kind":"protected_interpreter"});
    sql.execute(
        "UPDATE runs SET metadata_json = ?1 WHERE run_id = 'run'",
        [labeled.to_string()],
    )
    .unwrap();
    let verified = prepared.verify_settled(&store, "instance", "run").unwrap();
    assert_eq!(
        verified.observation().judgment.outcome,
        whipplescript_core::norm_evidence::TestOutcome::Fail
    );
    assert_eq!(
        verified.observation().observation_integrity,
        ObserverIntegrity::Cooperative {}
    );
    let mut relocated = prepared.clone();
    relocated.request.url = "https://new-executor/exec".into();
    assert_eq!(
        relocated
            .verify_settled(&store, "instance", "run")
            .unwrap()
            .observation()
            .judgment,
        verified.observation().judgment
    );
    drop(sql);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn recovery_retains_the_failed_run_while_its_effect_retries_and_later_succeeds() {
    use whipplescript_store::{EffectCompletion, RetryEffect, RunStart, SqliteStore};
    let prepared = prepared_fixture();
    let mut kernel = journal_execution(
        SqliteStore::open_in_memory().unwrap(),
        &prepared,
        &receipt(&prepared, true, false),
        true,
    );
    kernel
        .store_mut()
        .retry_effect(RetryEffect {
            instance_id: "instance",
            effect_id: "observe",
            retry_after: None,
            idempotency_key: Some("retry"),
        })
        .unwrap();
    for phase in 0..3 {
        if phase == 1 {
            kernel
                .store_mut()
                .start_run(RunStart {
                    instance_id: "instance",
                    effect_id: "observe",
                    run_id: "retry-run",
                    provider: "exec",
                    worker_id: "whip-exec",
                    lease_id: "retry-lease",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    metadata_json: "{}",
                })
                .unwrap();
        }
        if phase == 2 {
            kernel
                .store_mut()
                .complete_effect(EffectCompletion {
                    instance_id: "instance",
                    effect_id: "observe",
                    run_id: "retry-run",
                    provider: "exec",
                    worker_id: "whip-exec",
                    status: "completed",
                    exit_code: Some(0),
                    summary: Some("later attempt"),
                    metadata_json: "{}",
                    idempotency_key: Some("retry-complete"),
                })
                .unwrap();
        }
        let earlier = prepared
            .verify_settled(kernel.store(), "instance", "run")
            .unwrap();
        assert_eq!(
            earlier.observation().judgment.outcome,
            whipplescript_core::norm_evidence::TestOutcome::Fail
        );
        assert_eq!(earlier.observation().judgment.counterexamples.len(), 1);
        assert!(prepared
            .verify_settled(kernel.store(), "instance", "retry-run")
            .is_err());
    }
    kernel.store_mut().rebuild_projections("instance").unwrap();
    assert_eq!(
        prepared
            .verify_settled(kernel.store(), "instance", "run")
            .unwrap()
            .observation()
            .judgment
            .counterexamples
            .len(),
        1
    );
}

#[test]
fn reconstruction_uses_original_history_and_capture_after_retirement() {
    let (mut ledger, record) = fixture(Some(template()), true);
    let old = ledger.norm_view(&Boundary).unwrap();
    let captured = artifact("def allow(user): return False");
    let prepared = PreparedNormExecution::prepare(
        &history(&ledger),
        &Boundary,
        &captured,
        &script(),
        selection(&old.ledger, &record),
    )
    .unwrap();
    let original_intent = prepared.intent().clone();
    let kernel = journal_execution(
        whipplescript_store::SqliteStore::open_in_memory().unwrap(),
        &prepared,
        &receipt(&prepared, true, false),
        true,
    );
    drop(prepared);
    let current = &old.records[&record];
    let active = &old.effective_records[&record];
    ledger
        .append_norm_event(
            &sign(
                "retire",
                NormAct::Retire {
                    ledger: old.ledger.clone(),
                    authority: Some(old.authority_head.clone()),
                    vocabulary: current.vocabulary.clone(),
                    record: record.clone(),
                    previous: current.head.clone(),
                    revision: active.content_head.clone(),
                    activation: active.head.clone(),
                    status: "retired".into(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    assert!(ledger
        .norm_view(&Boundary)
        .unwrap()
        .requirement_inventory()
        .unwrap()
        .requirements
        .is_empty());
    let history = history(&ledger);
    assert!(kernel
        .store()
        .get_script_capability("observer")
        .unwrap()
        .is_none());
    let recovered = PreparedNormExecution::recover_with_artifacts(
        &history,
        &Boundary,
        &|cut| {
            assert_eq!(cut, "cut");
            Ok(artifact_at("def allow(user): return False", cut))
        },
        kernel.store(),
        "instance",
        "run",
    )
    .unwrap();
    assert_eq!(recovered.intent(), &original_intent);
    assert_eq!(
        recovered.observation().judgment.outcome,
        whipplescript_core::norm_evidence::TestOutcome::Fail
    );
    assert_eq!(recovered.observation().judgment.counterexamples.len(), 1);
    for wrong in [
        artifact("def allow(user): return True"),
        artifact_at("def allow(user): return False", "different-cut"),
    ] {
        assert!(PreparedNormExecution::recover_with_artifacts(
            &history,
            &Boundary,
            &|_| Ok(wrong.clone()),
            kernel.store(),
            "instance",
            "run"
        )
        .is_err());
    }
    for (instance, run) in [("missing", "run"), ("instance", "missing")] {
        assert!(PreparedNormExecution::recover_settled(
            &history,
            &Boundary,
            &captured,
            kernel.store(),
            instance,
            run
        )
        .is_err());
    }
}

#[test]
fn reconstruction_refuses_journal_claims_that_do_not_rebind_to_authoritative_inputs() {
    use whipplescript_store::SqliteStore;
    let (ledger, record) = fixture(Some(template()), true);
    let view = ledger.norm_view(&Boundary).unwrap();
    let history = history(&ledger);
    let captured = artifact("def allow(user): return False");
    let prepared = PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &captured,
        &script(),
        selection(&view.ledger, &record),
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!(
        "norm-reconstruction-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    drop(journal_execution(
        SqliteStore::open(&path).unwrap(),
        &prepared,
        &receipt(&prepared, false, false),
        false,
    ));
    let store = SqliteStore::open(&path).unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    for pointer in [
        "/norm_intent/anchor/checkpoint/ledger",
        "/norm_intent/anchor/checkpoint/authority_head",
        "/norm_intent/requirement/name",
        "/norm_intent/requirement/version",
        "/norm_intent/requirement/digest",
        "/norm_intent/artifact/cut",
        "/norm_intent/artifact/manifest",
        "/norm_intent/effect_id",
        "/norm_intent/publisher",
        "/capability",
        "/stdin/method_definition_json",
        "/stdin/contract_json",
        "/stdin/files/main.py",
    ] {
        let mut input = prepared.effect_input().clone();
        *input.pointer_mut(pointer).unwrap() = json!("foreign");
        sql.execute(
            "UPDATE effects SET input_json = ?1 WHERE effect_id = 'observe'",
            [input.to_string()],
        )
        .unwrap();
        assert!(
            PreparedNormExecution::recover_settled(
                &history, &Boundary, &captured, &store, "instance", "run"
            )
            .is_err(),
            "{pointer}"
        );
    }
    for value in [json!(null), json!({"unknown":"intent"})] {
        let mut input = prepared.effect_input().clone();
        input["norm_intent"] = value;
        sql.execute(
            "UPDATE effects SET input_json = ?1 WHERE effect_id = 'observe'",
            [input.to_string()],
        )
        .unwrap();
        assert!(PreparedNormExecution::recover_settled(
            &history, &Boundary, &captured, &store, "instance", "run"
        )
        .is_err());
    }
    let mut input = prepared.effect_input().clone();
    input["norm_intent"]["anchor"]["frontier"] = json!([]);
    sql.execute(
        "UPDATE effects SET input_json = ?1 WHERE effect_id = 'observe'",
        [input.to_string()],
    )
    .unwrap();
    assert!(PreparedNormExecution::recover_settled(
        &history, &Boundary, &captured, &store, "instance", "run"
    )
    .is_err());
    sql.execute(
        "UPDATE effects SET input_json = ?1 WHERE effect_id = 'observe'",
        [prepared.effect_input().to_string()],
    )
    .unwrap();
    assert_eq!(
        PreparedNormExecution::recover_settled(
            &history, &Boundary, &captured, &store, "instance", "run"
        )
        .unwrap()
        .observation()
        .judgment
        .outcome,
        whipplescript_core::norm_evidence::TestOutcome::Pass
    );
    drop(sql);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

fn enqueue_kernel() -> (
    crate::RuntimeKernel<whipplescript_store::SqliteStore>,
    String,
    String,
) {
    let mut kernel = crate::RuntimeKernel::new(
        whipplescript_store::SqliteStore::open_in_memory().expect("enqueue store"),
    );
    let version = kernel
        .create_program_version(crate::ProgramVersionInput {
            program_name: "NormEnqueue",
            source_hash: "v1",
            ir_hash: "v1",
            compiler_version: "fixture",
            ir_snapshot: None,
        })
        .expect("program version");
    let instance = kernel.create_instance(&version, "{}").expect("instance");
    (kernel, instance, version.program_id)
}
#[test]
fn norm_enqueue_is_durable_idempotent_and_keeps_ordinary_script_policy() {
    use whipplescript_store::{CapabilityBinding, CapabilitySchemaRegistration, RunStart};
    let prepared = prepared_fixture();
    let (mut kernel, instance, program) = enqueue_kernel();
    let committed = prepared.enqueue(&mut kernel, &instance, Some(120)).unwrap();
    assert_eq!(
        prepared.enqueue(&mut kernel, &instance, Some(120)).unwrap(),
        committed
    );
    let effects = kernel.store().list_effects(&instance).unwrap();
    assert_eq!(effects.len(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&effects[0].input_json).unwrap(),
        *prepared.effect_input()
    );
    assert_eq!(
        serde_json::from_str::<Value>(&effects[0].required_capabilities_json).unwrap(),
        json!([format!("script.{}", prepared.capability)])
    );
    let start = RunStart {
        instance_id: &instance,
        effect_id: &prepared.intent.effect_id,
        run_id: "norm-run",
        provider: "exec",
        worker_id: "whip-exec",
        lease_id: "norm-lease",
        lease_expires_at: "2099-01-01T00:00:00Z",
        metadata_json: "{}",
    };
    assert!(matches!(
        kernel.store_mut().start_run(start),
        Err(StoreError::PolicyBlocked { .. })
    ));
    assert!(kernel.store().list_runs(&instance).unwrap().is_empty());
    let capability = format!("script.{}", prepared.capability);
    kernel
        .store_mut()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: &capability,
            description: "fixture host grant",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    kernel
        .store_mut()
        .bind_capability(CapabilityBinding {
            binding_id: "norm-binding",
            program_id: Some(&program),
            capability: &capability,
            provider: "builtin-script",
            config_json: "{}",
        })
        .unwrap();
    kernel.store_mut().start_run(start).unwrap();
    let events = kernel.store().list_events(&instance).unwrap();
    assert_eq!(
        prepared.enqueue(&mut kernel, &instance, Some(120)).unwrap(),
        committed
    );
    assert_eq!(
        kernel.store().list_effects(&instance).unwrap()[0].status,
        "running"
    );
    assert_eq!(kernel.store().list_events(&instance).unwrap(), events);
    assert!(matches!(
        prepared.enqueue(&mut kernel, &instance, Some(121)),
        Err(StoreError::Conflict(_))
    ));
    let mut changed = prepared.clone();
    changed.input["norm_intent"]["publisher"] = json!("another");
    assert!(matches!(
        changed.enqueue(&mut kernel, &instance, Some(120)),
        Err(StoreError::Conflict(_))
    ));
}
#[test]
fn norm_enqueue_requires_existing_running_instance() {
    use whipplescript_store::InstanceTransition;
    let prepared = prepared_fixture();
    let (mut kernel, instance, _) = enqueue_kernel();
    assert!(matches!(
        prepared.enqueue(&mut kernel, "absent", None),
        Err(StoreError::Conflict(_))
    ));
    assert!(kernel.store().list_events("absent").unwrap().is_empty());
    kernel
        .store_mut()
        .transition_instance(InstanceTransition {
            instance_id: &instance,
            status: "paused",
            reason: None,
            idempotency_key: Some("done"),
        })
        .unwrap();
    let events = kernel.store().list_events(&instance).unwrap();
    assert!(matches!(
        prepared.enqueue(&mut kernel, &instance, None),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(kernel.store().list_events(&instance).unwrap(), events);
    assert!(kernel.store().list_effects(&instance).unwrap().is_empty());
}
#[test]
fn norm_enqueue_refuses_missing_original_revision() {
    let prepared = prepared_fixture();
    let path = std::env::temp_dir().join(format!(
        "norm-enqueue-revision-{}.sqlite",
        std::process::id()
    ));
    let mut kernel =
        crate::RuntimeKernel::new(whipplescript_store::SqliteStore::open(&path).unwrap());
    let version = kernel
        .create_program_version(crate::ProgramVersionInput {
            program_name: "NormEnqueue",
            source_hash: "v1",
            ir_hash: "v1",
            compiler_version: "fixture",
            ir_snapshot: None,
        })
        .unwrap();
    let instance = kernel.create_instance(&version, "{}").unwrap();
    prepared.enqueue(&mut kernel, &instance, None).unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    sql.execute(
        "UPDATE effects SET program_version_id = NULL WHERE effect_id = ?1",
        [&prepared.intent.effect_id],
    )
    .unwrap();
    assert!(matches!(
        prepared.enqueue(&mut kernel, &instance, None),
        Err(StoreError::Conflict(_))
    ));
    drop(sql);
    drop(kernel);
    std::fs::remove_file(path).unwrap();
}

fn dispatch_plan(prepared: &PreparedNormExecution) -> ExecDispatchPlan {
    ExecDispatchPlan::prepare(
        "observer",
        prepared.request().body["script_sha256"]
            .as_str()
            .expect("prepared executor request has a script digest"),
        prepared.effect_input(),
        prepared.request(),
        "epoch",
        None,
        None,
    )
}

#[test]
fn norm_dispatch_binding_refuses_each_changed_execution_dimension() {
    let prepared = prepared_fixture();
    let plan = dispatch_plan(&prepared);
    validate_norm_dispatch(prepared.effect_input(), &plan).unwrap();
    // Ordinary scripts retain their independent cache/parse policies.
    let mut ordinary = plan.clone();
    ordinary.content_key = Some("cached".into());
    ordinary.parse_contract = Some(json!({"schema":"json"}));
    validate_norm_dispatch(&json!({"mode":"capability"}), &ordinary).unwrap();
    for dimension in ["body", "epoch", "cache", "parse"] {
        let mut changed = plan.clone();
        match dimension {
            "body" => changed.request_body_sha256 = "different".into(),
            "epoch" => changed.environment_epoch = "different".into(),
            "cache" => changed.content_key = Some("cached".into()),
            "parse" => changed.parse_contract = Some(Value::Null),
            _ => unreachable!(),
        }
        assert!(
            validate_norm_dispatch(prepared.effect_input(), &changed).is_err(),
            "{dimension}"
        );
    }
    for dimension in ["missing", "unknown", "null", "extra", "type", "intent"] {
        let mut input = prepared.effect_input().clone();
        match dimension {
            "missing" => {
                input.as_object_mut().unwrap().remove("norm_dispatch");
            }
            "unknown" => input["norm_dispatch"]["protocol"] = json!("future"),
            "null" => input["norm_dispatch"] = Value::Null,
            "extra" => input["norm_dispatch"]["extra"] = json!(true),
            "type" => input["norm_dispatch"]["environment_epoch"] = json!(3),
            "intent" => {
                input.as_object_mut().unwrap().remove("norm_intent");
            }
            _ => unreachable!(),
        }
        assert!(
            validate_norm_dispatch(&input, &plan).is_err(),
            "{dimension}"
        );
    }
    let mut moved = plan;
    moved.request_sha256 = "different-endpoint-same-body".into();
    validate_norm_dispatch(prepared.effect_input(), &moved).unwrap();
}

#[test]
fn norm_dispatch_binding_preserves_exact_legacy_terminal_recovery_only() {
    use whipplescript_store::SqliteStore;
    let current = prepared_fixture();
    let mut legacy = current.clone();
    legacy
        .input
        .as_object_mut()
        .unwrap()
        .remove("norm_dispatch");
    assert!(validate_norm_dispatch(legacy.effect_input(), &dispatch_plan(&legacy)).is_err());
    let kernel = journal_execution(
        SqliteStore::open_in_memory().unwrap(),
        &legacy,
        &receipt(&legacy, false, false),
        false,
    );
    assert!(current
        .verify_settled(kernel.store(), "instance", "run")
        .is_err());
    let (ledger, _) = fixture(Some(template()), true);
    let captured_history = history(&ledger);
    let captured_artifact = artifact("def allow(user): return False");
    let recovered = PreparedNormExecution::recover_settled(
        &captured_history,
        &Boundary,
        &captured_artifact,
        kernel.store(),
        "instance",
        "run",
    )
    .unwrap();
    assert_eq!(recovered.intent(), legacy.intent());
    assert_eq!(
        recovered.observation().judgment.outcome,
        whipplescript_core::norm_evidence::TestOutcome::Pass
    );
    // An unrecognized historical field is not another supported legacy shape.
    legacy.input["extra"] = json!(true);
    let changed = journal_execution(
        SqliteStore::open_in_memory().unwrap(),
        &legacy,
        &receipt(&legacy, false, false),
        false,
    );
    assert!(PreparedNormExecution::recover_settled(
        &captured_history,
        &Boundary,
        &captured_artifact,
        changed.store(),
        "instance",
        "run",
    )
    .is_err());
}

#[test]
fn norm_publication_verified_bridge_preserves_reports_and_recovers_receipts() {
    use crate::norm_publication::{ObservationSigning, PreparedObservationPublication};
    use whipplescript_store::norm_commands::NormCommandStore;
    for (actual, timeout) in [(false, false), (true, false), (true, true)] {
        let (mut ledger, requirement) = fixture_with_observation(Some(template()), true, true);
        let captured = history(&ledger);
        let ledger_id = captured.anchor().checkpoint.ledger;
        let execution = PreparedNormExecution::prepare(
            &captured,
            &Boundary,
            &artifact("def allow(user): return False"),
            &script(),
            selection(&ledger_id, &requirement),
        )
        .unwrap();
        let kernel = journal_execution(
            whipplescript_store::SqliteStore::open_in_memory().unwrap(),
            &execution,
            &receipt(&execution, actual, timeout),
            actual || timeout,
        );
        let verified = execution
            .verify_settled(kernel.store(), "instance", "run")
            .unwrap();
        let vocabulary = Vocabulary::new(observation_vocabulary().definition)
            .unwrap()
            .reference()
            .clone();
        let actor = actor();
        let signing = || ObservationSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-10T00:00:00Z",
        };
        let before = kernel.store().list_events("instance").unwrap();
        let mut wrong_actor = actor.clone();
        wrong_actor.principal = "different-publisher".into();
        assert!(PreparedObservationPublication::prepare(
            &verified,
            &captured,
            kernel.store(),
            &Boundary,
            ObservationSigning {
                actor: &wrong_actor,
                ..signing()
            },
            |_| panic!("wrong publisher must refuse before signing")
        )
        .is_err());
        assert_eq!(kernel.store().list_events("instance").unwrap(), before);
        assert!(PreparedObservationPublication::prepare(
            &verified,
            &captured,
            kernel.store(),
            &Boundary,
            signing(),
            |_| Ok("invalid-signature".into())
        )
        .is_err());
        assert_eq!(kernel.store().list_events("instance").unwrap(), before);
        let prepared = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            kernel.store(),
            &Boundary,
            signing(),
            |statement| Ok(sha256_hex(&statement.signing_bytes().unwrap())),
        )
        .unwrap();
        let NormAct::Create { fields_json, .. } = &prepared.event().statement.action else {
            panic!("observation create")
        };
        let fields: Value = serde_json::from_str(fields_json).unwrap();
        let report: Value =
            serde_json::from_str(fields["observation_json"].as_str().unwrap()).unwrap();
        assert_eq!(
            report,
            serde_json::to_value(verified.observation()).unwrap()
        );
        let before_recovery = kernel.store().list_events("instance").unwrap();
        assert!(
            PreparedObservationPublication::prepare(
                &verified,
                &captured,
                kernel.store(),
                &Boundary,
                ObservationSigning {
                    actor: &wrong_actor,
                    ..signing()
                },
                |_| panic!("changed recovery publisher must not sign")
            )
            .is_err(),
            "recovery cannot change the requested publishing principal"
        );
        assert_eq!(
            kernel.store().list_events("instance").unwrap(),
            before_recovery
        );
        let before_ledger = ledger.tracker_history().unwrap().len();
        // Crash before submission: preparing again never calls the signer.
        let recovered = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            kernel.store(),
            &Boundary,
            signing(),
            |_| panic!("recovery must not sign"),
        )
        .unwrap();
        assert_eq!(recovered.event(), prepared.event());
        let mut rotated_config = actor.clone();
        rotated_config.key_id = "new-key-configuration".into();
        let after_rotation = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            kernel.store(),
            &Boundary,
            ObservationSigning {
                actor: &rotated_config,
                created_at: "later",
                authority: Some("new-authority"),
                ..signing()
            },
            |_| panic!("key configuration changes must not replace retained signatures"),
        )
        .unwrap();
        assert_eq!(after_rotation.event(), prepared.event());
        let mut changed = verified.clone();
        changed.intent.publisher = "other-publisher".into();
        assert!(PreparedObservationPublication::prepare(
            &changed,
            &captured,
            kernel.store(),
            &Boundary,
            signing(),
            |_| panic!("retained slot must not re-sign")
        )
        .is_err());
        let mut changed = verified.clone();
        changed
            .observation
            .diagnostics
            .push("different verified observation".into());
        assert!(PreparedObservationPublication::prepare(
            &changed,
            &captured,
            kernel.store(),
            &Boundary,
            signing(),
            |_| panic!("retained slot must not re-sign")
        )
        .is_err());

        let receipt = recovered.submit(&mut ledger, &Boundary).unwrap();
        // Lost ledger response before runtime acknowledgment: exact resubmission.
        let replay = recovered.submit(&mut ledger, &Boundary).unwrap();
        assert_eq!(replay.event_id(), receipt.event_id());
        assert_eq!(ledger.tracker_history().unwrap().len(), before_ledger + 1);
        let acknowledgment = replay.acknowledge(kernel.store()).unwrap();
        assert_eq!(receipt.acknowledge(kernel.store()).unwrap(), acknowledgment);
    }
}

struct MisreportedReceipt<'a, S>(&'a mut S);
impl<S: whipplescript_store::norm_commands::NormCommandStore>
    whipplescript_store::norm_commands::NormCommandStore for MisreportedReceipt<'_, S>
{
    fn norm_state(&self, verifier: &dyn NormVerifier) -> StoreResult<NormView> {
        self.0.norm_state(verifier)
    }
    fn local_norm_aliases(&self) -> StoreResult<std::collections::BTreeMap<String, String>> {
        self.0.local_norm_aliases()
    }
    fn tracker_history(&self) -> StoreResult<Vec<whipplescript_store::items::TrackerEvent>> {
        self.0.tracker_history()
    }
    fn append_norm(
        &mut self,
        event: &SignedNormEvent,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<String> {
        self.0.append_norm(event, verifier)?;
        Ok("different-ledger-receipt".into())
    }
    fn import_norm(
        &mut self,
        events: &[whipplescript_store::items::TrackerEvent],
        verifier: &dyn NormVerifier,
    ) -> StoreResult<usize> {
        self.0.import_norm(events, verifier)
    }
}

#[test]
fn norm_publication_refuses_misreported_ledger_receipt_and_recovers_original() {
    use crate::norm_publication::{ObservationSigning, PreparedObservationPublication};
    use whipplescript_store::norm_commands::NormCommandStore;
    let (mut ledger, requirement) = fixture_with_observation(Some(template()), true, true);
    let captured = history(&ledger);
    let ledger_id = captured.anchor().checkpoint.ledger;
    let execution = PreparedNormExecution::prepare(
        &captured,
        &Boundary,
        &artifact("def allow(user): return False"),
        &script(),
        selection(&ledger_id, &requirement),
    )
    .unwrap();
    let kernel = journal_execution(
        whipplescript_store::SqliteStore::open_in_memory().unwrap(),
        &execution,
        &receipt(&execution, false, false),
        false,
    );
    let verified = execution
        .verify_settled(kernel.store(), "instance", "run")
        .unwrap();
    let vocabulary = Vocabulary::new(observation_vocabulary().definition)
        .unwrap()
        .reference()
        .clone();
    let actor = actor();
    let publication = PreparedObservationPublication::prepare(
        &verified,
        &captured,
        kernel.store(),
        &Boundary,
        ObservationSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-10T00:00:00Z",
        },
        |statement| Ok(sha256_hex(&statement.signing_bytes().unwrap())),
    )
    .unwrap();
    let before = kernel.store().list_events("instance").unwrap();
    let ledger_count = ledger.tracker_history().unwrap().len();
    assert!(publication
        .submit(&mut MisreportedReceipt(&mut ledger), &Boundary)
        .is_err());
    assert_eq!(kernel.store().list_events("instance").unwrap(), before);
    assert_eq!(ledger.tracker_history().unwrap().len(), ledger_count + 1);
    let receipt = publication.submit(&mut ledger, &Boundary).unwrap();
    assert_eq!(
        receipt.event_id(),
        publication.event().tracker_event().unwrap().event_id
    );
    receipt.acknowledge(kernel.store()).unwrap();
    assert_eq!(ledger.tracker_history().unwrap().len(), ledger_count + 1);
}

#[test]
fn norm_publication_concurrent_key_rotation_recovers_the_valid_winner() {
    use crate::norm_publication::{ObservationSigning, PreparedObservationPublication};
    use whipplescript_store::norm_commands::NormCommandStore;
    struct RotatingBoundary;
    impl NormVerifier for RotatingBoundary {
        fn verify(&self, who: &NormActor, bytes: &[u8], signature: &str) -> Result<(), String> {
            let mut successor = actor();
            successor.key_id = "successor".into();
            if (who == &actor() || who == &successor) && signature == sha256_hex(bytes) {
                Ok(())
            } else {
                Err("fixture key binding mismatch".into())
            }
        }
        fn authorize_creation(&self, creator: &str, owner: &NormActor) -> Result<(), String> {
            Boundary.authorize_creation(creator, owner)
        }
    }
    let boundary = RotatingBoundary;
    for request_successor in [false, true] {
        let (mut ledger, requirement) = fixture_with_observation(Some(template()), true, true);
        let captured = history(&ledger);
        let ledger_id = captured.anchor().checkpoint.ledger;
        let execution = PreparedNormExecution::prepare(
            &captured,
            &boundary,
            &artifact("def allow(user): return False"),
            &script(),
            selection(&ledger_id, &requirement),
        )
        .unwrap();
        let kernel = journal_execution(
            whipplescript_store::SqliteStore::open_in_memory().unwrap(),
            &execution,
            &receipt(&execution, false, false),
            false,
        );
        let verified = execution
            .verify_settled(kernel.store(), "instance", "run")
            .unwrap();
        let vocabulary = Vocabulary::new(observation_vocabulary().definition)
            .unwrap()
            .reference()
            .clone();
        let actor = actor();
        let mut successor = actor.clone();
        successor.key_id = "successor".into();
        let before_denied = kernel.store().list_events("instance").unwrap();
        assert!(
            PreparedObservationPublication::prepare(
                &verified,
                &captured,
                kernel.store(),
                &boundary,
                ObservationSigning {
                    vocabulary: &vocabulary,
                    authority: None,
                    actor: &successor,
                    created_at: "t0"
                },
                |statement| Ok(sha256_hex(&statement.signing_bytes().unwrap())),
            )
            .is_err(),
            "authentication of a successor key does not grant current creation authority"
        );
        assert_eq!(
            kernel.store().list_events("instance").unwrap(),
            before_denied
        );
        let mut selected_event = None;
        let before = ledger.tracker_history().unwrap().len();
        let publication = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            kernel.store(),
            &boundary,
            ObservationSigning {
                vocabulary: &vocabulary,
                authority: None,
                actor: if request_successor {
                    &successor
                } else {
                    &actor
                },
                created_at: "2026-09-10T00:00:00Z",
            },
            |statement| {
                // First preparation has read an empty slot. While it signs, a
                // legitimate key rotation and a second preparation win the slot.
                let state = ledger.norm_state(&boundary).unwrap();
                let mut rotation = sign(
                    "rotate-during-publication",
                    NormAct::Rotate {
                        ledger: state.ledger,
                        previous: state.authority_head,
                        successor: successor.clone(),
                        frontier: state.frontier.into_iter().collect(),
                    },
                );
                rotation.successor_signature =
                    Some(sha256_hex(&rotation.statement.signing_bytes().unwrap()));
                let authority = ledger.append_norm(&rotation, &boundary).unwrap();
                let winner_history = CapturedNormHistory::capture(
                    &ledger.norm_state(&boundary).unwrap(),
                    &ledger.tracker_history().unwrap(),
                    &boundary,
                    whipplescript_store::norm_history::NormHistoryLimits::default(),
                )
                .unwrap();
                let winner = PreparedObservationPublication::prepare(
                    &verified,
                    &winner_history,
                    kernel.store(),
                    &boundary,
                    ObservationSigning {
                        vocabulary: &vocabulary,
                        authority: Some(&authority),
                        actor: &successor,
                        created_at: "2026-09-10T00:00:01Z",
                    },
                    |statement| Ok(sha256_hex(&statement.signing_bytes().unwrap())),
                )
                .unwrap();
                selected_event = Some(winner.event().clone());
                Ok(sha256_hex(&statement.signing_bytes().unwrap()))
            },
        )
        .unwrap();
        assert_eq!(publication.event(), &selected_event.unwrap());
        assert_eq!(publication.event().statement.actor, successor);
        let receipt = publication.submit(&mut ledger, &boundary).unwrap();
        receipt.acknowledge(kernel.store()).unwrap();
        assert_eq!(ledger.tracker_history().unwrap().len(), before + 2);
    }
}

#[test]
fn norm_publication_external_signatures_bind_recovered_report_before_retention() {
    use crate::norm_publication::{
        ObservationPublicationDraft, ObservationSigning, PreparedObservationPublication,
    };
    for actual in [false, true] {
        let (mut ledger, requirement) = fixture_with_observation(Some(template()), true, true);
        let captured = history(&ledger);
        let artifact = artifact("def allow(user): return False");
        let prepared = PreparedNormExecution::prepare(
            &captured,
            &Boundary,
            &artifact,
            &script(),
            selection(&captured.anchor().checkpoint.ledger, &requirement),
        )
        .unwrap();
        let kernel = journal_execution(
            whipplescript_store::SqliteStore::open_in_memory().unwrap(),
            &prepared,
            &receipt(&prepared, actual, false),
            actual,
        );
        let execution = prepared
            .verify_settled(kernel.store(), "instance", "run")
            .unwrap();
        let vocabulary = Vocabulary::new(observation_vocabulary().definition)
            .unwrap()
            .reference()
            .clone();
        let actor = actor();
        let signing = || ObservationSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "t1",
        };
        let mut other_actor = actor.clone();
        other_actor.principal = "other-publisher".into();
        assert!(PreparedObservationPublication::draft(
            &execution,
            &captured,
            kernel.store(),
            &Boundary,
            ObservationSigning {
                actor: &other_actor,
                ..signing()
            }
        )
        .is_err());
        assert!(PreparedObservationPublication::draft(
            &execution,
            &captured,
            kernel.store(),
            &Boundary,
            ObservationSigning {
                created_at: "",
                ..signing()
            }
        )
        .is_err());
        let before = kernel.store().list_events("instance").unwrap();
        let ObservationPublicationDraft::Unsigned { statement } =
            PreparedObservationPublication::draft(
                &execution,
                &captured,
                kernel.store(),
                &Boundary,
                signing(),
            )
            .unwrap()
        else {
            panic!("empty slot must draft")
        };
        assert_eq!(kernel.store().list_events("instance").unwrap(), before);
        let sign_statement = |statement: NormStatement| {
            let signature = crate::exec_http::sha256_hex(&statement.signing_bytes().unwrap());
            SignedNormEvent {
                statement,
                signature,
                successor_signature: None,
            }
        };
        let event = sign_statement(statement);
        let mut changed = event.statement.clone();
        let NormAct::Create { fields_json, .. } = &mut changed.action else {
            unreachable!()
        };
        let mut fields: Value = serde_json::from_str(fields_json).unwrap();
        fields["observation_json"] = json!("{}");
        *fields_json = fields.to_string();
        let changed_report = sign_statement(changed);
        let mut wrong_nonce = event.statement.clone();
        wrong_nonce.nonce = "caller-nonce".into();
        let wrong_nonce = sign_statement(wrong_nonce);
        let mut invalid_signature = event.clone();
        invalid_signature.signature = "invalid".into();
        let mut wrong_principal = event.statement.clone();
        wrong_principal.actor.principal = "other-publisher".into();
        let wrong_principal = sign_statement(wrong_principal);
        let mut non_create = event.statement.clone();
        non_create.action = NormAct::Bootstrap {
            creator: "owner".into(),
            charter: NormCharter::bundled().unwrap(),
        };
        let non_create = sign_statement(non_create);
        let mut extra_signature = event.clone();
        extra_signature.successor_signature = Some("unrequested".into());
        for retained in [false, true] {
            if retained {
                PreparedObservationPublication::prepare_signed(
                    &execution,
                    &captured,
                    kernel.store(),
                    &Boundary,
                    &event,
                )
                .unwrap();
            }
            let before = kernel.store().list_events("instance").unwrap();
            for wrong in [
                &changed_report,
                &wrong_nonce,
                &invalid_signature,
                &wrong_principal,
                &non_create,
                &extra_signature,
            ] {
                assert!(PreparedObservationPublication::prepare_signed(
                    &execution,
                    &captured,
                    kernel.store(),
                    &Boundary,
                    wrong
                )
                .is_err());
                assert_eq!(kernel.store().list_events("instance").unwrap(), before);
            }
        }
        let ObservationPublicationDraft::Retained { event: recovered } =
            PreparedObservationPublication::draft(
                &execution,
                &captured,
                kernel.store(),
                &Boundary,
                ObservationSigning {
                    created_at: "later",
                    ..signing()
                },
            )
            .unwrap()
        else {
            panic!("retained envelope must survive")
        };
        assert_eq!(recovered, event);
        let publication = PreparedObservationPublication::prepare_signed(
            &execution,
            &captured,
            kernel.store(),
            &Boundary,
            &recovered,
        )
        .unwrap();
        let receipt = publication.submit(&mut ledger, &Boundary).unwrap();
        let acknowledgment = receipt.acknowledge(kernel.store()).unwrap();
        assert_eq!(receipt.acknowledge(kernel.store()).unwrap(), acknowledgment);
        let current = history(&ledger);
        assert!(
            current.preview_creation(&event.statement).is_err(),
            "unsigned nonce reuse refuses"
        );
        assert!(
            current.preflight(&event, &Boundary).is_ok(),
            "exact signed ledger recovery remains admissible"
        );
        assert!(
            current.preflight(&changed_report, &Boundary).is_err(),
            "a different signed event cannot reuse the admitted nonce"
        );
        let mut fresh = event.statement.clone();
        fresh.nonce = "fresh-preview".into();
        assert!(current.preview_creation(&fresh).is_ok());
        assert!(current.preview_creation(&non_create.statement).is_err());
    }
}

#[test]
fn norm_enqueue_host_preparation_recovers_retained_selection_after_history_advances() {
    let (mut ledger_store, requirement) = fixture(Some(template()), true);
    let original_history = history(&ledger_store);
    let ledger = original_history.anchor().checkpoint.ledger;
    let captured = artifact("def allow(user): return False");
    let installed = script();
    let (mut kernel, instance, _) = enqueue_kernel();
    let prepare = |history, installed, selection| {
        PreparedNormExecution::prepare_enqueue(
            kernel.store(),
            &instance,
            NormEnqueuePreparation {
                history,
                verifier: &Boundary,
                artifact: &captured,
                installed,
                capability: "observer",
                selection,
            },
        )
    };
    assert!(prepare(&original_history, None, selection(&ledger, &requirement)).is_err());
    let mut empty_identity = selection(&ledger, &requirement);
    empty_identity.effect_id = " ";
    assert!(prepare(&original_history, Some(&installed), empty_identity).is_err());
    let mut wrong_registration = installed.clone();
    wrong_registration.name = "another".into();
    assert!(prepare(
        &original_history,
        Some(&wrong_registration),
        selection(&ledger, &requirement)
    )
    .is_err());
    let prepared = prepare(
        &original_history,
        Some(&installed),
        selection(&ledger, &requirement),
    )
    .unwrap();
    let acknowledgment = prepared.enqueue(&mut kernel, &instance, Some(120)).unwrap();
    let record = ledger_store.norm_view(&Boundary).unwrap().records[&requirement].clone();
    ledger_store
        .append_norm_event(
            &sign(
                "advance",
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: record.vocabulary,
                    fields_json: record.fields.to_string(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let advanced = history(&ledger_store);
    assert_ne!(
        original_history.anchor().frontier,
        advanced.anchor().frontier
    );
    kernel
        .store_mut()
        .transition_instance(whipplescript_store::InstanceTransition {
            instance_id: &instance,
            status: "paused",
            reason: None,
            idempotency_key: Some("pause-after-enqueue"),
        })
        .unwrap();
    let events = kernel.store().list_events(&instance).unwrap();
    let current_frontier: Vec<_> = advanced.anchor().frontier.into_iter().collect();
    let original_frontier: Vec<_> = original_history.anchor().frontier.into_iter().collect();
    for explicit in [None, Some(original_frontier.as_slice())] {
        let mut selected = selection(&ledger, &requirement);
        selected.frontier = explicit;
        selected.environment_epoch = "host-has-changed";
        let replay = PreparedNormExecution::prepare_enqueue(
            kernel.store(),
            &instance,
            NormEnqueuePreparation {
                history: &advanced,
                verifier: &Boundary,
                artifact: &captured,
                installed: None,
                capability: "observer",
                selection: selected,
            },
        )
        .unwrap();
        assert_eq!(replay.effect_input(), prepared.effect_input());
        assert_eq!(
            replay.enqueue(&mut kernel, &instance, Some(120)).unwrap(),
            acknowledgment
        );
        assert!(replay.enqueue(&mut kernel, &instance, Some(121)).is_err());
    }
    for mismatch in ["frontier", "publisher", "capability", "artifact"] {
        let changed_artifact = artifact("def allow(user): return True");
        let mut selected = selection(&ledger, &requirement);
        if mismatch == "frontier" {
            selected.frontier = Some(&current_frontier);
        }
        if mismatch == "publisher" {
            selected.publisher = "another";
        }
        assert!(
            PreparedNormExecution::prepare_enqueue(
                kernel.store(),
                &instance,
                NormEnqueuePreparation {
                    history: &advanced,
                    verifier: &Boundary,
                    artifact: if mismatch == "artifact" {
                        &changed_artifact
                    } else {
                        &captured
                    },
                    installed: None,
                    capability: if mismatch == "capability" {
                        "another"
                    } else {
                        "observer"
                    },
                    selection: selected,
                }
            )
            .is_err(),
            "{mismatch}"
        );
    }
    assert_eq!(kernel.store().list_events(&instance).unwrap(), events);
    assert!(kernel.store().list_runs(&instance).unwrap().is_empty());
}

#[test]
fn recovered_execution_binds_selection_to_the_original_contract_and_exercise() {
    use whipplescript_core::norm_evidence::evaluate_report;
    for (actual, timeout) in [(false, false), (true, false), (true, true)] {
        let (ledger, requirement) = fixture(Some(template()), true);
        let captured = history(&ledger);
        let source = artifact("def allow(user): return False");
        let prepared = PreparedNormExecution::prepare(
            &captured,
            &Boundary,
            &source,
            &script(),
            selection(&captured.anchor().checkpoint.ledger, &requirement),
        )
        .unwrap();
        let expected: ReportContract = serde_json::from_str(
            prepared.request().body["stdin"]["contract_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let kernel = journal_execution(
            whipplescript_store::SqliteStore::open_in_memory().unwrap(),
            &prepared,
            &receipt(&prepared, actual, timeout),
            actual || timeout,
        );
        drop(prepared);
        let recovered = PreparedNormExecution::recover_settled(
            &captured,
            &Boundary,
            &source,
            kernel.store(),
            "instance",
            "run",
        )
        .unwrap();
        assert_eq!(recovered.contract(), &expected);
        let report = &recovered.observation().report;
        assert!(recovered.verify_report_binding(report));
        assert_eq!(
            evaluate_report(recovered.contract(), report, &recovered),
            recovered.observation().judgment
        );
        let exercised = &report.observations[0];
        assert!(recovered.verify_assertion_exercise(report, exercised));
        let mut invented = exercised.clone();
        invented.witness.push_str("-invented");
        assert!(!recovered.verify_assertion_exercise(report, &invented));
        let mut substituted = report.clone();
        substituted.observations[0].actual = json!(!actual);
        assert!(!recovered.verify_report_binding(&substituted));
        assert!(!recovered.verify_assertion_exercise(&substituted, exercised));
        substituted = report.clone();
        substituted.subject.artifact.push_str("-different");
        assert!(!recovered.verify_report_binding(&substituted));
        assert_eq!(
            recovered.observation().observation_integrity,
            ObserverIntegrity::Cooperative {}
        );
    }
}

/// DR-0123: the engineering charter carries the kernel's observation
/// declaration under the publishing scope, so a verified execution's
/// observation lands in an engineering ledger through the existing
/// publication path, and can then be offered as support for the
/// requirement's exact revision through the charter's own relation.
#[test]
fn engineering_charter_receives_a_verified_observation_through_publication() {
    use crate::norm_publication::{ObservationSigning, PreparedObservationPublication};
    let charter: NormCharter =
        serde_json::from_str(include_str!("../../../examples/engineering/charter.json"))
            .expect("the engineering charter is a charter");
    let mut ledger = whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
    let ledger_id = ledger
        .append_norm_event(
            &sign(
                "root",
                NormAct::Bootstrap {
                    creator: "owner".into(),
                    charter: charter.clone(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let reference = |name: &str| {
        Vocabulary::new(
            charter
                .vocabularies
                .iter()
                .find(|entry| entry.definition.name == name)
                .unwrap_or_else(|| panic!("charter declares {name}"))
                .definition
                .clone(),
        )
        .unwrap()
        .reference()
        .clone()
    };
    let mut fields = json!({
        "name": "allow", "proposition": "unknown denied", "domain": "workspace",
        "subject": "main.py", "applicability": "every candidate", "owner": "owner"
    });
    fields["support_contract"] = json!(template().to_string());
    let requirement = ledger
        .append_norm_event(
            &sign(
                "requirement",
                NormAct::Create {
                    ledger: ledger_id.clone(),
                    authority: None,
                    vocabulary: reference("requirement"),
                    fields_json: fields.to_string(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    ledger
        .append_norm_event(
            &sign(
                "accept",
                NormAct::Transition {
                    ledger: ledger_id.clone(),
                    authority: None,
                    vocabulary: reference("requirement"),
                    record: requirement.clone(),
                    previous: requirement.clone(),
                    status: "accepted".into(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let captured = history(&ledger);
    let execution = PreparedNormExecution::prepare(
        &captured,
        &Boundary,
        &artifact("def allow(user): return False"),
        &script(),
        selection(&ledger_id, &requirement),
    )
    .unwrap();
    let kernel = journal_execution(
        whipplescript_store::SqliteStore::open_in_memory().unwrap(),
        &execution,
        &receipt(&execution, false, false),
        false,
    );
    let verified = execution
        .verify_settled(kernel.store(), "instance", "run")
        .unwrap();
    let observation_vocabulary = reference("local-observation");
    let actor = actor();
    let prepared = PreparedObservationPublication::prepare(
        &verified,
        &captured,
        kernel.store(),
        &Boundary,
        ObservationSigning {
            vocabulary: &observation_vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-18T00:00:00Z",
        },
        |statement| Ok(sha256_hex(&statement.signing_bytes().unwrap())),
    )
    .unwrap();
    let receipt = prepared.submit(&mut ledger, &Boundary).unwrap();
    let observation = receipt.event_id().to_string();
    let view = ledger.norm_view(&Boundary).unwrap();
    assert_eq!(
        view.records[&observation].vocabulary.name,
        "local-observation"
    );
    let r0 = view.effective_records[&requirement].content_head.clone();
    let support = view.relation_family("support").unwrap().basis;
    let statement = NormStatement {
        protocol: "whipplescript.norm/v1".into(),
        actor: actor.clone(),
        nonce: "supports".into(),
        created_at: "2026-09-18T00:00:00Z".into(),
        action: NormAct::Create {
            ledger: ledger_id.clone(),
            authority: None,
            vocabulary: reference("supports"),
            fields_json: json!({"source": observation, "target": r0}).to_string(),
        },
        premises: Some(NormPremises {
            family_basis: Some(support),
            references: vec![observation.clone(), r0.clone()],
            inventory_frontier: Vec::new(),
        }),
    };
    let signature = sha256_hex(&statement.signing_bytes().unwrap());
    ledger
        .append_norm_event(
            &SignedNormEvent {
                statement,
                signature,
                successor_signature: None,
            },
            &Boundary,
        )
        .unwrap();
    let family = ledger
        .norm_view(&Boundary)
        .unwrap()
        .relation_family("support")
        .unwrap();
    assert!(family.edges.iter().any(|edge| {
        edge.source == observation && edge.target == requirement && edge.relation == "supports"
    }));
}

/// DR-0124 §14.6: the wrapper publishes an artifact through the journal-retained
/// path a Home process already uses, keyed by the artifact's identity; the
/// ledger admits it under `build.publish`; a retry recovers the retained
/// envelope; a differing candidate for the same identity is refused; and a
/// task's `implements` edge to the artifact's revision is an ordinary relation.
#[test]
fn engineering_charter_receives_a_published_artifact_and_an_implements_edge() {
    use crate::norm_artifact_publication::{
        ArtifactSigning, BuildArtifact, PreparedArtifactPublication, INPUT_ROOT_ENCODING_V1,
    };
    let charter: NormCharter =
        serde_json::from_str(include_str!("../../../examples/engineering/charter.json"))
            .expect("the engineering charter is a charter");
    let mut ledger = whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
    let ledger_id = ledger
        .append_norm_event(
            &sign(
                "root",
                NormAct::Bootstrap {
                    creator: "owner".into(),
                    charter: charter.clone(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let reference = |name: &str| {
        Vocabulary::new(
            charter
                .vocabularies
                .iter()
                .find(|entry| entry.definition.name == name)
                .unwrap_or_else(|| panic!("charter declares {name}"))
                .definition
                .clone(),
        )
        .unwrap()
        .reference()
        .clone()
    };
    let task = ledger
        .append_norm_event(
            &sign(
                "task",
                NormAct::Create {
                    ledger: ledger_id.clone(),
                    authority: None,
                    vocabulary: reference("task"),
                    fields_json: json!({"title": "ship the parser", "labels": ["build"]})
                        .to_string(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let captured = history(&ledger);
    let journal = whipplescript_store::SqliteStore::open_in_memory().unwrap();
    let artifact = BuildArtifact {
        ledger: ledger_id.clone(),
        cut: "cut-a0".into(),
        label: "root//parser:parser".into(),
        configuration: "cfg:linux-x86_64".into(),
        outputs: vec![sha256_hex(b"parser binary")],
        classification: "low".into(),
        encoding: INPUT_ROOT_ENCODING_V1.into(),
        action: Some(sha256_hex(b"action")),
        projection: None,
    };
    let vocabulary = reference("artifact");
    let actor = actor();
    let signer = |statement: &NormStatement| Ok(sha256_hex(&statement.signing_bytes().unwrap()));
    // Without a durable build record the journal retains nothing.
    let unrecorded = PreparedArtifactPublication::prepare(
        &artifact,
        &"0".repeat(64),
        &captured,
        &journal,
        &Boundary,
        ArtifactSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-22T00:00:00Z",
        },
        signer,
    )
    .expect_err("an unrecorded build is not published");
    assert!(
        unrecorded.contains("durable record it names"),
        "{unrecorded}"
    );
    // The wrapper records the completed build, then publishes it.
    let build_record = journal
        .append_event(whipplescript_store::NewEvent {
            instance_id: &PreparedArtifactPublication::build_instance(&artifact),
            event_type: PreparedArtifactPublication::BUILD_RECORDED,
            payload_json: &serde_json::to_string(&artifact).unwrap(),
            source: "wrapper",
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
        })
        .unwrap()
        .event_id;
    let prepared = PreparedArtifactPublication::prepare(
        &artifact,
        &build_record,
        &captured,
        &journal,
        &Boundary,
        ArtifactSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-22T00:00:00Z",
        },
        signer,
    )
    .unwrap();
    // A retry for the same identity recovers the retained envelope without signing.
    let again = PreparedArtifactPublication::prepare(
        &artifact,
        &build_record,
        &captured,
        &journal,
        &Boundary,
        ArtifactSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-22T00:00:00Z",
        },
        |_| Err("a retained envelope is never re-signed".into()),
    )
    .unwrap();
    assert_eq!(again.event(), prepared.event());
    // A different candidate for the same identity is refused.
    let mut other = artifact.clone();
    other.outputs = vec![sha256_hex(b"another parser binary")];
    let refused = PreparedArtifactPublication::prepare(
        &other,
        &build_record,
        &captured,
        &journal,
        &Boundary,
        ArtifactSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-22T00:00:00Z",
        },
        signer,
    )
    .expect_err("a differing candidate is refused");
    assert!(refused.contains("differs from the artifact"), "{refused}");
    let receipt = prepared.submit(&mut ledger, &Boundary).unwrap();
    receipt.acknowledge(&journal).unwrap();
    let published = receipt.event_id().to_string();
    let view = ledger.norm_view(&Boundary).unwrap();
    let record = &view.records[&published];
    assert_eq!(record.vocabulary.name, "artifact");
    assert_eq!(record.status, "recorded");
    assert_eq!(record.fields["cut"], json!("cut-a0"));
    assert_eq!(record.fields["encoding"], json!(INPUT_ROOT_ENCODING_V1));
    assert_eq!(record.fields["classification"], json!("low"));
    // The task implements the artifact's exact revision, binding the family
    // basis and both references as premises.
    let basis = view.relation_family("implementation").unwrap().basis;
    let statement = NormStatement {
        protocol: "whipplescript.norm/v1".into(),
        actor: actor.clone(),
        nonce: "implements".into(),
        created_at: "2026-09-22T00:00:00Z".into(),
        action: NormAct::Create {
            ledger: ledger_id.clone(),
            authority: None,
            vocabulary: reference("implements"),
            fields_json: json!({"source": task, "target": published}).to_string(),
        },
        premises: Some(NormPremises {
            family_basis: Some(basis),
            references: vec![task.clone(), published.clone()],
            inventory_frontier: Vec::new(),
        }),
    };
    let signature = sha256_hex(&statement.signing_bytes().unwrap());
    ledger
        .append_norm_event(
            &SignedNormEvent {
                statement,
                signature,
                successor_signature: None,
            },
            &Boundary,
        )
        .unwrap();
    let family = ledger
        .norm_view(&Boundary)
        .unwrap()
        .relation_family("implementation")
        .unwrap();
    assert!(family.edges.iter().any(|edge| {
        edge.source == task && edge.target == published && edge.relation == "implements"
    }));
}

/// The projection producer (norm-plane §8, E4): a typed query at a frontier,
/// handed to a consumer as a pure value that says what it could not see.
#[test]
fn a_projection_is_the_query_at_its_frontier_and_nothing_more() {
    use crate::norm_query_producer::{project, ProjectedMembers, PROJECTION_PROTOCOL};
    let charter: NormCharter =
        serde_json::from_str(include_str!("../../../examples/engineering/charter.json"))
            .expect("the engineering charter is a charter");
    let mut ledger = whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
    let ledger_id = ledger
        .append_norm_event(
            &sign(
                "root",
                NormAct::Bootstrap {
                    creator: "owner".into(),
                    charter: charter.clone(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let reference = |name: &str| {
        Vocabulary::new(
            charter
                .vocabularies
                .iter()
                .find(|entry| entry.definition.name == name)
                .unwrap_or_else(|| panic!("charter declares {name}"))
                .definition
                .clone(),
        )
        .unwrap()
        .reference()
        .clone()
    };
    let task = ledger
        .append_norm_event(
            &sign(
                "task",
                NormAct::Create {
                    ledger: ledger_id.clone(),
                    authority: None,
                    vocabulary: reference("task"),
                    fields_json: json!({"title": "ship the parser", "labels": ["build"]})
                        .to_string(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let projected = project(
        &mut ledger,
        &Boundary,
        None,
        "vocabulary(task) & status(task, open)",
        None,
        None,
    )
    .expect("the query projects");
    assert_eq!(projected.protocol, PROJECTION_PROTOCOL);
    assert_eq!(
        projected.expression,
        "(vocabulary(task) & status(task, open))"
    );
    assert!(!projected.frontier.is_empty());
    assert_eq!(projected.cut, None);
    match &projected.members {
        ProjectedMembers::Records { records } => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].record, task);
            assert_eq!(records[0].vocabulary, "task");
            assert_eq!(records[0].status, "open");
        }
        other => panic!("records expected, got {other:?}"),
    }
    assert!(
        projected.completeness.complete,
        "{:?}",
        projected.completeness
    );
    // The same query at the same frontier is the same projection.
    let again = project(
        &mut ledger,
        &Boundary,
        None,
        "vocabulary(task) & status(task, open)",
        Some(projected.frontier.clone()),
        None,
    )
    .expect("projects again");
    assert_eq!(again.key(), projected.key());
    assert_eq!(again, projected);
    // A projection over the artifact needs the cut it is read at.
    let refused = project(
        &mut ledger,
        &Boundary,
        None,
        "anchored(path(src/**))",
        None,
        None,
    )
    .expect_err("no resource point");
    assert!(
        refused.contains("a query over the artifact needs a resource point: name the cut"),
        "{refused}"
    );
    let malformed = project(
        &mut ledger,
        &Boundary,
        None,
        "vocabulary(task) | path(src/**)",
        None,
        None,
    )
    .expect_err("mixed types");
    assert!(
        malformed.contains("region and record sets share operators but are different types"),
        "{malformed}"
    );
}
