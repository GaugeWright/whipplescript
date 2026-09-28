use super::*;
use crate::norm_execution::fixtures::*;
use crate::norm_execution::PreparedNormExecution;
use crate::norm_execution_policy::{
    Buck2TestsPolicy, EvidencePolicy, NativeEvidencePolicy, ProtectedPythonPolicy,
};
use crate::norm_planning::{plan, ImpactQuery, PlanningConfiguration};
use crate::norm_publication::{ObservationSigning, PreparedObservationPublication};
use whipplescript_core::norm_buck2_report::{
    CaseExecution, CaseStatus, ExecutionKind, SuiteReport, SuiteTarget,
};
use whipplescript_core::norm_evidence::{EvidenceDiagnostic, TestOutcome};
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::SqliteStore;

fn suite(name: &str, listing: Listing, executions: Vec<CaseExecution>) -> SuiteReport {
    SuiteReport {
        target: SuiteTarget {
            cell: "root".into(),
            package: "".into(),
            target: name.into(),
            configuration: "cfg".into(),
        },
        test_type: "whip".into(),
        labels: Vec::new(),
        listing,
        executions,
    }
}

fn listed(cases: &[&str]) -> Listing {
    Listing::Listed {
        cases: cases.iter().map(|case| (*case).into()).collect(),
        cacheable: true,
    }
}

fn execution(case: &str, status: CaseStatus, verdict_line: bool) -> CaseExecution {
    CaseExecution {
        case: case.into(),
        status,
        exit_code: Some(0),
        verdict_line,
        start_time_ms: 1,
        duration_ms: 1,
        execution_kind: ExecutionKind::Local,
        stdout_sha256: sha256_hex(case.as_bytes()),
        stderr_sha256: sha256_hex(b""),
        max_memory_used_bytes: None,
    }
}

fn report(cut: &str, suites: Vec<SuiteReport>) -> Buck2TestReport {
    Buck2TestReport {
        protocol: BUCK2_TEST_SUPPORT_PROTOCOL.into(),
        cut: Some(cut.into()),
        executor_user: None,
        trace_id: None,
        config_entries: Vec::new(),
        suites,
        exit_code: 0,
    }
}

fn passing_report() -> Buck2TestReport {
    report(
        "cut",
        vec![suite(
            "passing",
            listed(&["a", "b"]),
            vec![
                execution("a", CaseStatus::Pass, true),
                execution("b", CaseStatus::Pass, true),
            ],
        )],
    )
}

fn targets() -> Vec<String> {
    vec!["//:passing".into()]
}

/// The template a listing of `//:passing` with cases `a` and `b` infers.
fn support() -> Buck2TestsSupport {
    Buck2TestsSupport::infer(
        &targets(),
        &report(
            "cut",
            vec![suite("passing", listed(&["a", "b"]), Vec::new())],
        ),
    )
    .expect("the listing infers a template")
}

fn build() -> Buck2Build {
    Buck2Build {
        buck2_version: "2026-09-15".into(),
        toolchain: "buck2-version 2026-09-15".into(),
        environment: "whip-test-executor".into(),
    }
}

#[test]
fn a_check_command_is_split_without_a_shell_and_only_buck2_test_is_adapted() {
    assert_eq!(
        parse_check_command("  buck2 test //:passing root//pkg/sub:case-1 ").unwrap(),
        vec!["//:passing".to_owned(), "root//pkg/sub:case-1".to_owned()]
    );
    for (command, refusal) in [
        ("", "the check command is empty"),
        (
            "buck2 test //:a; rm -rf /",
            "the check command contains the shell metacharacter `;`; it is split without a shell",
        ),
        (
            "buck2 test $(targets)",
            "the check command contains the shell metacharacter `$`",
        ),
        (
            "buck2 test //:a\n//:b",
            "the check command contains the shell metacharacter `\\n`",
        ),
        (
            "pytest tests/",
            "no bundled adapter reports cases for `pytest`; only `buck2 test <targets>` is adapted",
        ),
        (
            "cargo test",
            "no bundled adapter reports cases for `cargo`; only `buck2 test <targets>` is adapted",
        ),
        (
            "buck2 build //:passing",
            "no bundled adapter reports cases for `buck2 build`; only `buck2 test <targets>` is adapted",
        ),
        (
            "buck2",
            "no bundled adapter reports cases for `buck2`; only `buck2 test <targets>` is adapted",
        ),
        ("buck2 test", "`buck2 test` names no targets"),
        (
            "buck2 test //...",
            "`//...` is not a Buck2 target label; name each target, since a flag or a pattern lets the runner choose what runs",
        ),
        (
            "buck2 test --no-remote-cache //:a",
            "`--no-remote-cache` is not a Buck2 target label",
        ),
        ("buck2 test //pkg:", "`//pkg:` is not a Buck2 target label"),
        ("buck2 test //pkg", "`//pkg` is not a Buck2 target label"),
        ("buck2 test pkg:a", "`pkg:a` is not a Buck2 target label"),
        ("buck2 test //:a/b", "`//:a/b` is not a Buck2 target label"),
        ("buck2 test //:a //:a", "the check command names `//:a` twice"),
    ] {
        let error = parse_check_command(command).unwrap_err();
        assert!(error.starts_with(refusal), "{command:?}: {error}");
    }
}

#[test]
fn inference_lists_each_suites_cases_and_refuses_a_failed_listing_or_a_missing_adapter() {
    let support = Buck2TestsSupport::infer(
        &["//:passing".into(), "//:swallowed".into()],
        &report(
            "cut",
            vec![
                suite(
                    "passing",
                    listed(&["parses_empty", "parses_nested"]),
                    Vec::new(),
                ),
                suite("swallowed", listed(&["accepts_grant"]), Vec::new()),
            ],
        ),
    )
    .unwrap();
    assert_eq!(support.targets(), ["//:passing", "//:swallowed"]);
    assert_eq!(
        support
            .cases()
            .iter()
            .map(|case| case.id.as_str())
            .collect::<Vec<_>>(),
        [
            "root//:passing::parses_empty",
            "root//:passing::parses_nested",
            "root//:swallowed::accepts_grant"
        ]
    );
    assert!(support
        .cases()
        .iter()
        .all(|case| case.assertion == VERDICT_ASSERTION && case.expected == json!("pass")));
    // The template is stored as the requirement's support contract, and read
    // back as the same template.
    let stored = serde_json::to_string(&support).unwrap();
    assert!(stored.contains(BUCK2_TESTS_SUPPORT_PROTOCOL), "{stored}");
    assert_eq!(
        serde_json::from_str::<Buck2TestsSupport>(&stored).unwrap(),
        support
    );

    let failed = Buck2TestsSupport::infer(
        &targets(),
        &report(
            "cut",
            vec![suite(
                "passing",
                Listing::ListingFailed {
                    reason: "the listing exited with status 2".into(),
                },
                Vec::new(),
            )],
        ),
    )
    .unwrap_err();
    assert_eq!(
        failed,
        "cannot infer the cases of `root//:passing`: its listing failed: the listing exited with status 2"
    );
    let unadapted = Buck2TestsSupport::infer(
        &targets(),
        &report(
            "cut",
            vec![suite(
                "passing",
                Listing::MissingAdapter {
                    test_type: "rust".into(),
                },
                Vec::new(),
            )],
        ),
    )
    .unwrap_err();
    assert_eq!(
        unadapted,
        "cannot infer the cases of `root//:passing`: no bundled adapter lists a test of type `rust`"
    );
    assert_eq!(
        Buck2TestsSupport::infer(&targets(), &report("cut", Vec::new())).unwrap_err(),
        "`buck2 test` over those targets handed the executor no test suite"
    );
}

#[test]
fn a_stored_template_is_validated_before_anything_runs_or_is_judged() {
    let Buck2TestsSupport::V1 { targets, cases } = support();
    let with = |targets: Vec<String>, cases: Vec<RequiredCase>| {
        Buck2TestsSupport::V1 { targets, cases }.validate()
    };
    assert_eq!(with(targets.clone(), cases.clone()), Ok(()));
    assert_eq!(
        with(Vec::new(), cases.clone()).unwrap_err(),
        "a Buck2 support template names no targets"
    );
    assert_eq!(
        with(vec!["//...".into()], cases.clone()).unwrap_err(),
        "a Buck2 support template names `//...`, which is not a target label"
    );
    assert_eq!(
        with(targets.clone(), Vec::new()).unwrap_err(),
        "a Buck2 support template declares no cases"
    );
    for (assertion, expected) in [("verdict", json!("fail")), ("exit", json!("pass"))] {
        let mut changed = cases.clone();
        changed[0].assertion = assertion.into();
        changed[0].expected = expected;
        assert_eq!(
            with(targets.clone(), changed).unwrap_err(),
            "a Buck2 test case asserts only its verdict, and expects it to pass"
        );
    }
}

#[test]
fn the_method_identity_commits_to_the_protocol_the_adapter_and_the_targets() {
    let method = support().method();
    assert_eq!(method.name, BUCK2_TESTS_METHOD);
    assert_eq!(method.version, "1");
    assert_eq!(
        method.digest,
        sha256_hex(
            json!([
                BUCK2_TESTS_SUPPORT_PROTOCOL,
                BUCK2_TESTS_ADAPTER,
                BUCK2_TEST_SUPPORT_PROTOCOL,
                ["//:passing"],
            ])
            .to_string()
            .as_bytes()
        )
    );
    // The cases are the requirement's, not the method's: another inventory
    // over the same targets is the same method.
    let Buck2TestsSupport::V1 { targets, mut cases } = support();
    cases.pop();
    assert_eq!(Buck2TestsSupport::V1 { targets, cases }.method(), method);
    let other = Buck2TestsSupport::V1 {
        targets: vec!["//:passing".into(), "//:swallowed".into()],
        cases: support().cases().to_vec(),
    };
    assert_ne!(other.method(), method);
}

/// A ledger whose accepted requirement declares the Buck2 template, with the
/// observation vocabulary a run is published under.
fn ledger_with(template: &Buck2TestsSupport) -> (WorkItemStore, String) {
    fixture_with_observation(Some(json!(template)), true, true)
}

fn selection_for<'a>(ledger: &'a str, requirement: &'a str) -> Buck2RunSelection<'a> {
    Buck2RunSelection {
        ledger,
        frontier: None,
        requirement,
        effect_id: "buck2-run",
        publisher: "owner",
    }
}

/// Prepare and record a run of the requirement over `artifact`, with the
/// executor's report as given.
fn recorded(
    ledger: &WorkItemStore,
    requirement: &str,
    artifact: &CapturedArtifact,
    journal: &SqliteStore,
    executor_report: Option<Buck2TestReport>,
) -> (PreparedBuck2Run, String) {
    let history = history(ledger);
    let prepared = PreparedBuck2Run::prepare(
        &history,
        &Boundary,
        artifact,
        selection_for(&history.anchor().checkpoint.ledger, requirement),
    )
    .expect("fixture");
    let (run, _) = prepared
        .record(journal, build(), executor_report)
        .expect("fixture");
    (prepared, run)
}

fn judged(
    ledger: &WorkItemStore,
    artifact: &CapturedArtifact,
    journal: &SqliteStore,
    run: &str,
) -> whipplescript_core::norm_evidence::TestJudgment {
    VerifiedBuck2Execution::recover_captured(
        &history(ledger),
        &Boundary,
        artifact,
        journal,
        &run_instance("cut"),
        run,
    )
    .expect("fixture")
    .judgment()
}

#[test]
fn a_recorded_run_is_rejudged_from_its_retained_report_against_the_declared_inventory() {
    let (ledger, requirement) = ledger_with(&support());
    let artifact = artifact("print('fixture')");
    let passing = |executions: Vec<CaseExecution>, listing: &[&str]| {
        report("cut", vec![suite("passing", listed(listing), executions)])
    };
    use CaseStatus::{Fail, Pass, Unknown};
    for (executor_report, outcome, diagnostic) in [
        // Both declared cases pass: tested support.
        (Some(passing_report()), TestOutcome::Pass, None),
        // A new case the runner lists is not required, and does not count.
        (
            Some(passing(
                vec![
                    execution("a", Pass, true),
                    execution("b", Pass, true),
                    execution("c", Fail, true),
                ],
                &["a", "b", "c"],
            )),
            TestOutcome::Pass,
            None,
        ),
        // A declared case the runner no longer lists is missing, never a
        // smaller denominator.
        (
            Some(passing(vec![execution("a", Pass, true)], &["a"])),
            TestOutcome::HarnessFailed,
            Some(EvidenceDiagnostic::MissingCase("root//:passing::b".into())),
        ),
        // A failing verdict is counterevidence.
        (
            Some(passing(
                vec![execution("a", Pass, true), execution("b", Fail, true)],
                &["a", "b"],
            )),
            TestOutcome::Fail,
            None,
        ),
        // A case that exits without a verdict line is not exercised.
        (
            Some(passing(
                vec![execution("a", Pass, true), execution("b", Unknown, false)],
                &["a", "b"],
            )),
            TestOutcome::HarnessFailed,
            Some(EvidenceDiagnostic::TruncatedReport),
        ),
        // No report at all is a named harness failure.
        (
            None,
            TestOutcome::HarnessFailed,
            Some(EvidenceDiagnostic::MissingReport),
        ),
        // A report for another cut is not this run's.
        (
            Some(Buck2TestReport {
                cut: Some("another-cut".into()),
                ..passing_report()
            }),
            TestOutcome::HarnessFailed,
            Some(EvidenceDiagnostic::UnboundReport),
        ),
    ] {
        let journal = SqliteStore::open_in_memory().unwrap();
        let (_, run) = recorded(&ledger, &requirement, &artifact, &journal, executor_report);
        let judgment = judged(&ledger, &artifact, &journal, &run);
        assert_eq!(judgment.outcome, outcome, "{judgment:?}");
        if let Some(diagnostic) = diagnostic {
            assert!(judgment.diagnostics.contains(&diagnostic), "{judgment:?}");
        }
        if outcome == TestOutcome::Fail {
            assert_eq!(judgment.counterexamples.len(), 1);
            assert_eq!(judgment.counterexamples[0].case, "root//:passing::b");
            assert_eq!(judgment.counterexamples[0].actual, json!("fail"));
        }
        // The denominator is the declaration's, whatever the runner listed.
        assert_eq!(
            judgment.required,
            ["root//:passing::a", "root//:passing::b"]
                .map(String::from)
                .into()
        );
    }
}

#[test]
fn recovery_rebuilds_the_run_from_verified_history_and_refuses_what_differs() {
    let (ledger, requirement) = ledger_with(&support());
    let artifact = artifact("print('fixture')");
    let journal = SqliteStore::open_in_memory().unwrap();
    let (prepared, run) = recorded(
        &ledger,
        &requirement,
        &artifact,
        &journal,
        Some(passing_report()),
    );
    // Recording the same run again returns it; a different one refuses.
    assert_eq!(
        prepared
            .record(&journal, build(), Some(passing_report()))
            .unwrap()
            .0,
        run
    );
    assert_eq!(
        prepared.record(&journal, build(), None).unwrap_err(),
        "this effect already recorded a different Buck2 run"
    );
    let captured = history(&ledger);
    let recovered = VerifiedBuck2Execution::recover(
        &captured,
        &Boundary,
        &|cut: &str| Ok(artifact_at("print('fixture')", cut)),
        &journal,
        &prepared.instance(),
        &run,
    )
    .unwrap();
    assert_eq!(recovered.intent(), prepared.intent());
    assert_eq!(recovered.contract(), prepared.contract());
    assert_eq!(recovered.judgment().outcome, TestOutcome::Pass);
    assert_eq!(
        recovered.contract().subject.artifact,
        crate::norm_runner::candidate_identity(artifact.files())
    );

    // A record that is not in the journal is missing, not empty.
    assert_eq!(
        VerifiedBuck2Execution::recover_captured(
            &captured,
            &Boundary,
            &artifact,
            &journal,
            &prepared.instance(),
            "no-such-run",
        )
        .unwrap_err(),
        "the Buck2 run's record is missing from the journal"
    );
    // A record whose method is not the one verified history's template
    // names, or whose cut holds other bytes, is not reconstructed.
    let mut tampered: Buck2RunRecord = serde_json::from_str(
        &journal
            .list_events(&prepared.instance())
            .unwrap()
            .into_iter()
            .find(|event| event.event_id == run)
            .unwrap()
            .payload_json,
    )
    .unwrap();
    tampered.intent.method.digest = "another adapter".into();
    tampered.intent.effect_id = "tampered".into();
    let forged = journal
        .append_event(whipplescript_store::NewEvent {
            instance_id: &prepared.instance(),
            event_type: BUCK2_TESTS_RECORDED,
            payload_json: &serde_json::to_string(&tampered).unwrap(),
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
        })
        .unwrap()
        .event_id;
    let refusal = "the recorded Buck2 run differs from its reconstruction from verified history";
    assert_eq!(
        VerifiedBuck2Execution::recover_captured(
            &captured,
            &Boundary,
            &artifact,
            &journal,
            &prepared.instance(),
            &forged,
        )
        .unwrap_err(),
        refusal
    );
    assert_eq!(
        VerifiedBuck2Execution::recover_captured(
            &captured,
            &Boundary,
            &artifact_at("print('changed')", "cut"),
            &journal,
            &prepared.instance(),
            &run,
        )
        .unwrap_err(),
        refusal
    );
    // A retry finds the recorded run by its effect, whatever the ledger's
    // frontier is now, and only for the same requirement and publisher.
    let ledger_id = captured.anchor().checkpoint.ledger;
    assert_eq!(
        PreparedBuck2Run::retried(&journal, "cut", &selection_for(&ledger_id, &requirement))
            .unwrap(),
        Some(run.clone())
    );
    assert_eq!(
        PreparedBuck2Run::retried(
            &journal,
            "another-cut",
            &selection_for(&ledger_id, &requirement)
        )
        .unwrap(),
        None
    );
    for change in ["publisher", "requirement"] {
        let mut selected = selection_for(&ledger_id, &requirement);
        match change {
            "publisher" => selected.publisher = "worker",
            _ => selected.requirement = "another",
        }
        assert_eq!(
            PreparedBuck2Run::retried(&journal, "cut", &selected).unwrap_err(),
            "this effect already recorded a Buck2 run of another requirement or publisher",
            "{change}"
        );
    }
    // A retry of the same effect under another preparation refuses.
    let other = PreparedBuck2Run::prepare(
        &captured,
        &Boundary,
        &artifact_at("print('changed')", "cut"),
        selection_for(&captured.anchor().checkpoint.ledger, &requirement),
    )
    .unwrap();
    assert_eq!(
        other.recorded(&journal).unwrap_err(),
        "this effect already recorded a Buck2 run of another preparation"
    );
}

#[test]
fn preparation_binds_only_a_buck2_template_and_its_own_selection() {
    let (ledger, requirement) = ledger_with(&support());
    let captured = history(&ledger);
    let ledger_id = captured.anchor().checkpoint.ledger;
    let artifact = artifact("print('fixture')");
    let prepared = PreparedBuck2Run::prepare(
        &captured,
        &Boundary,
        &artifact,
        selection_for(&ledger_id, &requirement),
    )
    .unwrap();
    assert_eq!(prepared.targets(), ["//:passing"]);
    assert_eq!(prepared.intent().protocol, BUCK2_RUN_PROTOCOL);
    assert_eq!(prepared.intent().method, support().method());
    assert_eq!(prepared.instance(), "buck2-tests:cut");
    assert!(is_run_instance(&prepared.instance()));
    assert!(!is_run_instance("instance"));
    for (change, refusal) in [
        (0, "norm preparation selected a different ledger"),
        (1, "a Buck2 run requires a publisher and an effect identity"),
        (2, "a Buck2 run requires a publisher and an effect identity"),
        (3, "norm preparation requires an active requirement"),
    ] {
        let mut selected = selection_for(&ledger_id, &requirement);
        match change {
            0 => selected.ledger = "foreign",
            1 => selected.publisher = " ",
            2 => selected.effect_id = "",
            _ => selected.requirement = "missing",
        }
        assert_eq!(
            PreparedBuck2Run::prepare(&captured, &Boundary, &artifact, selected).unwrap_err(),
            refusal
        );
    }
    // Each kind prepares only its own template.
    let (python, python_requirement) = fixture(Some(template()), true);
    let python_history = history(&python);
    assert_eq!(
        PreparedBuck2Run::prepare(
            &python_history,
            &Boundary,
            &artifact,
            selection_for(
                &python_history.anchor().checkpoint.ledger,
                &python_requirement
            ),
        )
        .unwrap_err(),
        "norm requirement's support template calls Python, not Buck2 tests"
    );
    assert_eq!(
        PreparedNormExecution::prepare(
            &captured,
            &Boundary,
            &artifact,
            &script(),
            selection(&ledger_id, &requirement),
        )
        .unwrap_err(),
        "norm requirement's support template runs Buck2 tests, not Python calls"
    );
    // A stored template that no longer validates refuses to prepare.
    let Buck2TestsSupport::V1 { targets, .. } = support();
    let (empty, empty_requirement) = ledger_with(&Buck2TestsSupport::V1 {
        targets,
        cases: Vec::new(),
    });
    let empty_history = history(&empty);
    assert_eq!(
        PreparedBuck2Run::prepare(
            &empty_history,
            &Boundary,
            &artifact,
            selection_for(
                &empty_history.anchor().checkpoint.ledger,
                &empty_requirement
            ),
        )
        .unwrap_err(),
        "a Buck2 support template declares no cases"
    );
}

/// Publish a recorded run's observation into the ledger.
fn publish(ledger: &mut WorkItemStore, journal: &SqliteStore, instance: &str, run: &str) -> String {
    let captured = history(ledger);
    let execution = VerifiedBuck2Execution::recover(
        &captured,
        &Boundary,
        &|cut: &str| Ok(artifact_at("print('fixture')", cut)),
        journal,
        instance,
        run,
    )
    .expect("fixture");
    let vocabulary = Vocabulary::new(observation_vocabulary().definition)
        .expect("fixture")
        .reference()
        .clone();
    let publication = PreparedObservationPublication::prepare(
        &execution,
        &captured,
        journal,
        &Boundary,
        ObservationSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor(),
            created_at: "t1",
        },
        |statement| Ok(sha256_hex(&statement.signing_bytes().expect("fixture"))),
    )
    .expect("fixture");
    // The retention rests on the run's durable record.
    let retained: Vec<_> = journal
        .list_events(instance)
        .expect("fixture")
        .into_iter()
        .filter(|event| event.event_type == "norm.publication.prepared")
        .collect();
    assert_eq!(retained.len(), 1);
    assert!(
        retained[0].payload_json.contains(&format!(
            "\"basis\":{{\"kind\":\"event\",\"event_id\":\"{run}\"}}"
        )),
        "{}",
        retained[0].payload_json
    );
    let receipt = publication.submit(ledger, &Boundary).expect("fixture");
    receipt.acknowledge(journal).expect("fixture");
    receipt.event_id().to_owned()
}

/// The name a requirement's signed invocations carry.
fn requirement_name(ledger: &WorkItemStore, requirement: &str) -> String {
    let view = ledger.norm_view(&Boundary).expect("fixture");
    view.requirement_inventory().expect("fixture").requirements[requirement]
        .requirement
        .clone()
        .expect("fixture")
        .name
}

fn planning(ledger: &WorkItemStore, requirement: &str) -> PlanningConfiguration {
    let view = ledger.norm_view(&Boundary).expect("fixture");
    let observation = Vocabulary::new(observation_vocabulary().definition)
        .expect("fixture")
        .reference()
        .clone();
    PlanningConfiguration::parse(
        &json!({"capability":"observer","roles":[
            {"vocabulary":view.records[requirement].vocabulary,"interpretation":"context"},
            {"vocabulary":observation,"interpretation":"published_execution"},
        ]})
        .to_string(),
    )
    .expect("fixture")
}

fn planned(
    ledger: &WorkItemStore,
    requirement: &str,
    journal: &SqliteStore,
    candidate: &str,
    policy: &dyn EvidencePolicy,
) -> crate::norm_planning::Planned {
    let captured = history(ledger);
    let configuration = planning(ledger, requirement);
    let candidate = candidate.to_owned();
    let artifacts = move |cut: &str| {
        Ok(artifact_at(
            if cut == "cut" {
                "print('fixture')"
            } else {
                &candidate
            },
            cut,
        ))
    };
    plan(
        ImpactQuery {
            configuration: &configuration,
            history: &captured,
            verifier: &Boundary,
            runtime: journal,
            artifacts: &artifacts,
            before_cut: "candidate",
            after_cut: "candidate",
            before_frontier: None,
            after_frontier: None,
            policy,
        },
        |_| unreachable!("a Buck2 requirement never verifies a Python runtime"),
    )
    .expect("fixture")
}

fn work(planned: &crate::norm_planning::Planned, requirement: &str) -> serde_json::Value {
    serde_json::to_value(&planned.plan.requirements[requirement][0].work).expect("fixture")
}

fn protected_runtime() -> String {
    json!({
        "engine": {"kind": "cpython3147_wasi", "artifact_path": "/opt/reactor.wasm", "artifact_sha256": "a".repeat(64)},
        "executable": "whip",
        "python_version": "3.14.7",
        "environment": "epoch",
    })
    .to_string()
}

#[test]
fn a_published_run_supports_its_requirement_on_a_host_that_runs_buck2_and_nowhere_else() {
    let (mut ledger, requirement) = ledger_with(&support());
    let artifact = artifact("print('fixture')");
    let journal = SqliteStore::open_in_memory().unwrap();
    let (prepared, run) = recorded(
        &ledger,
        &requirement,
        &artifact,
        &journal,
        Some(passing_report()),
    );
    // Only the prepared publisher may sign the run's observation.
    let captured = history(&ledger);
    let execution = VerifiedBuck2Execution::recover_captured(
        &captured,
        &Boundary,
        &artifact,
        &journal,
        &prepared.instance(),
        &run,
    )
    .unwrap();
    let observation = Vocabulary::new(observation_vocabulary().definition)
        .unwrap()
        .reference()
        .clone();
    let worker = whipplescript_store::norm::NormActor {
        principal: "worker".into(),
        ..actor()
    };
    assert_eq!(
        PreparedObservationPublication::prepare(
            &execution,
            &captured,
            &journal,
            &Boundary,
            ObservationSigning {
                vocabulary: &observation,
                authority: None,
                actor: &worker,
                created_at: "t1",
            },
            |_| panic!("a refused signer is never asked to sign"),
        )
        .err()
        .as_deref(),
        Some("observation signer differs from prepared publisher")
    );
    let published = publish(&mut ledger, &journal, &prepared.instance(), &run);

    let buck2 = Buck2TestsPolicy::new("captured").unwrap();
    assert!(buck2.runs_buck2_tests());
    // The same bytes at the candidate: the run's support carries.
    let same = planned(&ledger, &requirement, &journal, "print('fixture')", &buck2);
    assert_eq!(
        work(&same, &requirement)["kind"],
        "supported",
        "{}",
        same.to_json()
    );
    assert!(same.plan.evidence_gaps.is_empty());
    // A changed file is another tested artifact: the requirement is checked
    // again with its Buck2 method.
    let changed = planned(&ledger, &requirement, &journal, "print('changed')", &buck2);
    assert_eq!(
        work(&changed, &requirement),
        json!({"kind":"check","method":support().method()}),
        "{}",
        changed.to_json()
    );
    // The native host's policy names both kinds and accepts the run too.
    let python = || ProtectedPythonPolicy::new(&protected_runtime(), "captured").unwrap();
    let native =
        NativeEvidencePolicy::new(python(), Buck2TestsPolicy::new("captured").unwrap()).unwrap();
    assert!(native.runs_buck2_tests());
    assert_ne!(native.identity(), buck2.identity());
    let native_plan = planned(&ledger, &requirement, &journal, "print('fixture')", &native);
    assert_eq!(work(&native_plan, &requirement)["kind"], "supported");
    assert_eq!(
        NativeEvidencePolicy::new(python(), Buck2TestsPolicy::new("another time").unwrap())
            .err()
            .as_deref(),
        Some("a native evidence policy's kinds share one time basis")
    );
    assert_eq!(
        Buck2TestsPolicy::new(" ").err().as_deref(),
        Some("Buck2 evidence policy requires an explicit time basis")
    );

    // A host that runs no Buck2 reads the publication as unavailable, never
    // as support.
    assert!(!python().runs_buck2_tests());
    let elsewhere = planned(
        &ledger,
        &requirement,
        &journal,
        "print('fixture')",
        &python(),
    );
    assert_eq!(
        serde_json::to_value(&elsewhere.plan.evidence_gaps[&published]).unwrap(),
        json!({"kind":"execution_unavailable","reason":BUCK2_UNAVAILABLE,"requirement":requirement_name(&ledger, &requirement)})
    );
    assert_eq!(work(&elsewhere, &requirement)["kind"], "verify_evidence");
}

#[test]
fn only_a_host_that_runs_buck2_schedules_a_buck2_requirement() {
    let (ledger, requirement) = ledger_with(&support());
    let journal = SqliteStore::open_in_memory().unwrap();
    let buck2 = Buck2TestsPolicy::new("captured").unwrap();
    let scheduled = planned(&ledger, &requirement, &journal, "print('fixture')", &buck2);
    assert_eq!(
        work(&scheduled, &requirement),
        json!({"kind":"check","method":support().method()})
    );
    assert!(scheduled.method_gaps.is_empty());
    let python = ProtectedPythonPolicy::new(&protected_runtime(), "captured").unwrap();
    let unscheduled = planned(&ledger, &requirement, &journal, "print('fixture')", &python);
    assert_eq!(work(&unscheduled, &requirement)["kind"], "observation_gap");
    assert_eq!(
        unscheduled.method_gaps[&requirement][0].reason,
        BUCK2_UNAVAILABLE
    );
    // A stored template that no longer validates is a method gap, not a check.
    let Buck2TestsSupport::V1 { targets, .. } = support();
    let (empty, empty_requirement) = ledger_with(&Buck2TestsSupport::V1 {
        targets,
        cases: Vec::new(),
    });
    let invalid = planned(
        &empty,
        &empty_requirement,
        &journal,
        "print('fixture')",
        &buck2,
    );
    assert_eq!(
        work(&invalid, &empty_requirement)["kind"],
        "observation_gap"
    );
    assert_eq!(
        invalid.method_gaps[&empty_requirement][0].reason,
        "a Buck2 support template declares no cases"
    );
}
