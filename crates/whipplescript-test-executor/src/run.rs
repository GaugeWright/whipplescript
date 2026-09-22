//! Running the suites Buck2 handed over: each listing and each case is its
//! own execution through the orchestrator.

use std::collections::BTreeMap;

use prost_types::Duration as ProtoDuration;
use tonic::transport::Channel;
use whipplescript_core::norm_buck2_report::{
    Buck2TestReport, CaseExecution, CaseStatus, Listing, SuiteReport, SuiteTarget,
    BUCK2_TEST_SUPPORT_PROTOCOL,
};

use crate::args::Args;
use crate::executor::SpecCollector;
use crate::proto::buck::host_sharing::{
    host_sharing_requirements, weight_class, HostSharingRequirements, WeightClass,
};
use crate::proto::buck::test::test_orchestrator_client::TestOrchestratorClient;
use crate::proto::buck::test::{
    arg_value_content, execute_response2, external_runner_spec_value, test_stage, ArgValue,
    ArgValueContent, ConfiguredTargetHandle, EndOfTestResultsRequest, EnvironmentVariable,
    ExecuteRequest2, ExternalRunnerSpec, ExternalRunnerSpecValue, ReportTestResultRequest,
    ReportTestSessionRequest, ReportTestsDiscoveredRequest, TestExecutable, TestResult, TestStage,
    TestStatus, Testing,
};
use crate::report::{observe, whip_listing, whip_verdict, Observed};
use crate::transport;

/// The exit code Buck2's bundled runner returns when any test failed.
const FAILED: i32 = 32;

pub async fn serve(args: Args) -> Result<(), String> {
    let orchestrator = transport::client_channel(&args.orchestrator_addr, "orchestrator").await?;
    let (collector, specs) = SpecCollector::new();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn({
        let addr = args.executor_addr.clone();
        async move {
            transport::serve_executor(&addr, collector, async move {
                let _ = stopped.await;
            })
            .await
        }
    });
    let specs = specs
        .await
        .map_err(|_| "Buck2 closed the executor connection before the end of test requests")?;
    let outcome = run_all(&args, orchestrator, specs).await;
    let _ = stop.send(());
    server
        .await
        .map_err(|error| format!("the executor service task failed: {error}"))??;
    outcome
}

async fn run_all(
    args: &Args,
    channel: Channel,
    specs: Vec<ExternalRunnerSpec>,
) -> Result<(), String> {
    let mut client = TestOrchestratorClient::new(channel)
        .max_decoding_message_size(usize::MAX)
        .max_encoding_message_size(usize::MAX);
    client
        .report_test_session(ReportTestSessionRequest {
            session_info: format!("whip-test-executor {BUCK2_TEST_SUPPORT_PROTOCOL}"),
            test_session_id: None,
        })
        .await
        .map_err(|error| format!("cannot report the session: {error}"))?;
    let mut suites = Vec::with_capacity(specs.len());
    let mut all_passed = true;
    for spec in specs {
        let suite = run_suite(args, &mut client, spec).await?;
        if suite
            .executions
            .iter()
            .any(|execution| execution.status != CaseStatus::Pass)
            || !matches!(suite.listing, Listing::Listed { .. })
        {
            all_passed = false;
        }
        suites.push(suite);
    }
    let exit_code = if all_passed { 0 } else { FAILED };
    let report = Buck2TestReport {
        protocol: BUCK2_TEST_SUPPORT_PROTOCOL.into(),
        cut: args.cut.clone(),
        executor_user: std::env::var("BUCK2_TEST_EXECUTOR_USER").ok(),
        trace_id: args.trace_id.clone(),
        config_entries: args.config_entries.clone(),
        suites,
        exit_code,
    };
    let json = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    match &args.report {
        Some(path) => std::fs::write(path, json.as_bytes())
            .map_err(|error| format!("cannot write the report to {path}: {error}"))?,
        None => println!("{json}"),
    }
    client
        .end_of_test_results(EndOfTestResultsRequest { exit_code })
        .await
        .map_err(|error| format!("cannot report the end of test results: {error}"))?;
    Ok(())
}

fn spec_arg(value: ExternalRunnerSpecValue) -> ArgValue {
    ArgValue {
        content: Some(ArgValueContent {
            value: Some(arg_value_content::Value::SpecValue(value)),
        }),
        format: None,
    }
}

fn verbatim(value: &str) -> ExternalRunnerSpecValue {
    ExternalRunnerSpecValue {
        value: Some(external_runner_spec_value::Value::Verbatim(
            value.to_owned(),
        )),
    }
}

fn environment(
    spec_env: &BTreeMap<String, ExternalRunnerSpecValue>,
    extra: &[(&str, &str)],
) -> Vec<EnvironmentVariable> {
    let mut env: Vec<EnvironmentVariable> = spec_env
        .iter()
        .map(|(key, value)| EnvironmentVariable {
            key: key.clone(),
            value: Some(spec_arg(value.clone())),
        })
        .collect();
    for (key, value) in extra {
        env.push(EnvironmentVariable {
            key: (*key).to_owned(),
            value: Some(spec_arg(verbatim(value))),
        });
    }
    env
}

async fn execute(
    args: &Args,
    client: &mut TestOrchestratorClient<Channel>,
    target: Option<ConfiguredTargetHandle>,
    stage: TestStage,
    command: &[ExternalRunnerSpecValue],
    env: Vec<EnvironmentVariable>,
) -> Result<Option<Observed>, String> {
    let request = ExecuteRequest2 {
        timeout: Some(ProtoDuration {
            seconds: i64::try_from(args.timeout.as_secs()).unwrap_or(i64::MAX),
            nanos: 0,
        }),
        // An ordinary test: shared, weighing one permit.
        host_sharing_requirements: Some(HostSharingRequirements {
            requirements: Some(host_sharing_requirements::Requirements::Shared(
                host_sharing_requirements::Shared {
                    weight_class: Some(WeightClass {
                        value: Some(weight_class::Value::Permits(1)),
                    }),
                },
            )),
        }),
        test_executable: Some(TestExecutable {
            stage: Some(stage),
            target,
            cmd: command.iter().cloned().map(spec_arg).collect(),
            pre_create_dirs: Vec::new(),
            env,
        }),
        executor_override: None,
        required_local_resources: Vec::new(),
        disable_test_execution_caching: false,
    };
    let response = client
        .execute2(request)
        .await
        .map_err(|error| format!("Buck2 refused an execution: {error}"))?
        .into_inner();
    Ok(match response.response {
        Some(execute_response2::Response::Result(result)) => Some(observe(&result)),
        Some(execute_response2::Response::Cancelled(_)) | None => None,
    })
}

async fn run_suite(
    args: &Args,
    client: &mut TestOrchestratorClient<Channel>,
    spec: ExternalRunnerSpec,
) -> Result<SuiteReport, String> {
    let configured = spec.target.clone().unwrap_or_default();
    let target = SuiteTarget {
        cell: configured.cell.clone(),
        package: configured.package.clone(),
        target: configured.target.clone(),
        configuration: configured.configuration.clone(),
    };
    let handle = configured.handle;
    let suite = target.label();
    let env: BTreeMap<String, ExternalRunnerSpecValue> = spec.env.into_iter().collect();
    let mut executions = Vec::new();
    let listing = if spec.test_type == "whip" {
        let listing_stage = TestStage {
            item: Some(test_stage::Item::Listing(test_stage::Listing {
                suite: suite.clone(),
                cacheable: true,
            })),
        };
        match execute(
            args,
            client,
            handle,
            listing_stage,
            &spec.command,
            environment(&env, &[("WHIP_TEST_LIST", "1")]),
        )
        .await?
        {
            Some(observed) if observed.exit_code == Some(0) => {
                let cases = whip_listing(&observed.stdout);
                if cases.is_empty() {
                    Listing::ListingFailed {
                        reason: "the listing printed no cases".into(),
                    }
                } else {
                    Listing::Listed {
                        cases,
                        cacheable: true,
                    }
                }
            }
            Some(observed) => Listing::ListingFailed {
                reason: match observed.exit_code {
                    Some(code) => format!("the listing exited with status {code}"),
                    None => "the listing timed out".into(),
                },
            },
            None => Listing::ListingFailed {
                reason: "Buck2 cancelled the listing".into(),
            },
        }
    } else {
        Listing::MissingAdapter {
            test_type: spec.test_type.clone(),
        }
    };
    match &listing {
        Listing::Listed { cases, .. } => {
            client
                .report_tests_discovered(ReportTestsDiscoveredRequest {
                    target: handle,
                    testing: Some(Testing {
                        suite: suite.clone(),
                        testcases: cases.clone(),
                        variant: None,
                        repeat_count: None,
                    }),
                })
                .await
                .map_err(|error| format!("cannot report discovered tests: {error}"))?;
            for case in cases {
                let stage = TestStage {
                    item: Some(test_stage::Item::Testing(Testing {
                        suite: suite.clone(),
                        testcases: vec![case.clone()],
                        variant: None,
                        repeat_count: None,
                    })),
                };
                let execution = match execute(
                    args,
                    client,
                    handle,
                    stage,
                    &spec.command,
                    environment(&env, &[("WHIP_TEST_CASE", case)]),
                )
                .await?
                {
                    Some(observed) => {
                        let verdict = whip_verdict(&observed.stdout, case);
                        observed.case(case, verdict)
                    }
                    None => omitted(case),
                };
                report_result(client, handle, &suite, &execution).await?;
                executions.push(execution);
            }
        }
        Listing::ListingFailed { .. } | Listing::MissingAdapter { .. } => {
            // One command for the whole suite; its exit code stands in for a
            // verdict and the record says so.
            let stage = TestStage {
                item: Some(test_stage::Item::Testing(Testing {
                    suite: suite.clone(),
                    testcases: Vec::new(),
                    variant: None,
                    repeat_count: None,
                })),
            };
            let execution = match execute(
                args,
                client,
                handle,
                stage,
                &spec.command,
                environment(&env, &[]),
            )
            .await?
            {
                Some(observed) => observed.case(&suite, None),
                None => omitted(&suite),
            };
            report_result(client, handle, &suite, &execution).await?;
            executions.push(execution);
        }
    }
    Ok(SuiteReport {
        target,
        test_type: spec.test_type,
        labels: spec.labels,
        listing,
        executions,
    })
}

fn omitted(case: &str) -> CaseExecution {
    CaseExecution {
        case: case.to_owned(),
        status: CaseStatus::Omitted,
        exit_code: None,
        verdict_line: false,
        start_time_ms: 0,
        duration_ms: 0,
        execution_kind: whipplescript_core::norm_buck2_report::ExecutionKind::Unknown,
        stdout_sha256: crate::report::sha256_hex(b""),
        stderr_sha256: crate::report::sha256_hex(b""),
        max_memory_used_bytes: None,
    }
}

async fn report_result(
    client: &mut TestOrchestratorClient<Channel>,
    target: Option<ConfiguredTargetHandle>,
    suite: &str,
    execution: &CaseExecution,
) -> Result<(), String> {
    let status = match execution.status {
        CaseStatus::Pass => TestStatus::Pass,
        CaseStatus::Fail => TestStatus::Fail,
        CaseStatus::Timeout => TestStatus::Timeout,
        CaseStatus::Unknown => TestStatus::Unknown,
        CaseStatus::Omitted => TestStatus::Omitted,
    };
    let name = if execution.case == suite {
        suite.to_owned()
    } else {
        format!("{suite} - {}", execution.case)
    };
    client
        .report_test_result(ReportTestResultRequest {
            result: Some(TestResult {
                name,
                status: status as i32,
                msg: None,
                target,
                duration: Some(ProtoDuration {
                    seconds: i64::try_from(execution.duration_ms / 1000).unwrap_or(0),
                    nanos: i32::try_from((execution.duration_ms % 1000) * 1_000_000).unwrap_or(0),
                }),
                details: format!(
                    "status {:?}; exit {:?}; verdict line {}; stdout sha256 {}",
                    execution.status,
                    execution.exit_code,
                    execution.verdict_line,
                    execution.stdout_sha256
                ),
                max_memory_used_bytes: execution.max_memory_used_bytes,
            }),
        })
        .await
        .map_err(|error| format!("cannot report a test result: {error}"))?;
    Ok(())
}
