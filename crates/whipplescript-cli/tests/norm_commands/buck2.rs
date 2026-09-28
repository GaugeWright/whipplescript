//! A requirement declared by its Buck2 check (norm-plane §3.4, §14.5),
//! through the real `whip norm` CLI against a stand-in `buck2` that answers
//! what the wrapper asks it and writes the executor's report. The real Buck2
//! and executor run the same path in the CLI's `build_engine` fixture; this
//! one needs neither, so the bar's ordinary tests carry it.
use super::*;
use ring::signature::KeyPair;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_custody::client::UnixSocketTransport;
use whipplescript_kernel::norm_buck2_execution::{BUCK2_TESTS_RECORDED, BUCK2_UNAVAILABLE};
use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
use whipplescript_kernel::norm_execution::fixtures as execution;
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
use whipplescript_store::content::ContentStore;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};
use whipplescript_store::{NewEvent, RuntimeStore, SqliteStore};

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("norm JSON")
}

/// A stand-in `buck2`: it reports a version, resolves `//:passing` to one
/// configured target whose only input is `main.py`, and for `test` copies
/// `listing.json` (with `--list-only`) or `run.json` to the report path the
/// executor was given. The process environment is cleared, so every
/// program it runs is named absolutely.
fn fake_buck2(root: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("fake-buck2");
    let script = format!(
        r#"#!/bin/sh
case "$*" in *--version*) echo 'buck2 fake'; exit 0 ;; esac
sub=""
for a in "$@"; do case "$a" in cquery|audit|test) sub="$a"; break ;; esac; done
case "$sub" in
  cquery)
    case "$*" in
      *"deps("*) echo "root//:passing (fake//:configuration)" ;;
      *"inputs("*) echo "main.py" ;;
    esac
    exit 0 ;;
  audit) exit 0 ;;
  test)
    report=""; list=""; prev=""
    for a in "$@"; do
      [ "$prev" = --report ] && report="$a"
      [ "$a" = --list-only ] && list=1
      prev="$a"
    done
    if [ -n "$list" ]; then /bin/cp '{root}/listing.json' "$report"; else /bin/cp '{root}/run.json' "$report"; fi
    exit 0 ;;
esac
echo "unexpected buck2 $*" >&2
exit 1
"#,
        root = root.display()
    );
    std::fs::write(&path, script).expect("the stand-in buck2");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// The executor's report for the cut, with the passing suite's executions.
fn executor_report(executions: Value) -> Value {
    json!({
        "protocol": "whipplescript.norm.buck2-test-support/v1",
        "cut": "cut",
        "suites": [{
            "target": {"cell": "root", "package": "", "target": "passing", "configuration": "fake//:configuration"},
            "test_type": "whip",
            "labels": [],
            "listing": {"kind": "listed", "cases": ["parses_empty", "parses_nested"], "cacheable": true},
            "executions": executions,
        }],
        "exit_code": 0,
    })
}

fn case(name: &str, status: &str) -> Value {
    json!({
        "case": name, "status": status, "exit_code": 0, "verdict_line": true,
        "start_time_ms": 1, "duration_ms": 1, "execution_kind": "local",
        "stdout_sha256": "a".repeat(64), "stderr_sha256": "b".repeat(64),
    })
}

#[test]
fn norm_cli_declares_a_requirement_by_its_buck2_check_and_only_the_native_host_recovers_its_runs() {
    let fixture = Fixture::new();
    let mut charter = whipplescript_store::norm::NormCharter::bundled().unwrap();
    let observation = execution::observation_vocabulary();
    let observation_ref = Vocabulary::new(observation.definition.clone())
        .unwrap()
        .reference()
        .clone();
    let requirement_ref = Vocabulary::new(
        charter
            .vocabularies
            .iter()
            .find(|v| v.definition.name == "obligation")
            .unwrap()
            .definition
            .clone(),
    )
    .unwrap()
    .reference()
    .clone();
    charter.vocabularies.push(observation);
    charter.owner_scopes.push("observe.publish".into());
    fixture.write("charter.json", &json!(charter));
    fixture.run(&[
        "bootstrap",
        "--as",
        "owner",
        "--creator",
        "worker",
        "--charter",
        "charter.json",
    ]);

    // The cut: a build file and the one source the stand-in names as input.
    let mut branches = BranchStore::open(fixture.root.join("branches.sqlite")).unwrap();
    let content = ContentStore::open(fixture.root.join("content.sqlite")).unwrap();
    branches.ensure_mainline("t0").unwrap();
    let mut manifest = serde_json::Map::new();
    for (path, body) in [("BUCK", "# fixture\n"), ("main.py", "print('fixture')\n")] {
        manifest.insert(path.into(), json!(content.put(body.as_bytes()).unwrap()));
    }
    let manifest = content
        .put(Value::Object(manifest).to_string().as_bytes())
        .unwrap();
    branches
        .record_cut(CutRecord {
            cut_id: "cut",
            change_id: "cut",
            branch_id: MAINLINE_BRANCH_ID,
            manifest_hash: &manifest,
            parent_cut_id: None,
            origin: None,
            actor: None,
            intent: None,
            recorded_at: "t0",
        })
        .unwrap();
    drop(branches);

    let buck2 = fake_buck2(&fixture.root);
    let runtime_path = fixture.root.join("runtime.sqlite");
    std::fs::write(fixture.root.join("whip-test-executor"), b"").unwrap();
    let whip = |args: &[&str]| {
        fixture
            .command(args)
            .env("WHIPPLESCRIPT_BUCK2", &buck2)
            .env(
                "WHIPPLESCRIPT_TEST_EXECUTOR",
                fixture.root.join("whip-test-executor"),
            )
            .env("WHIPPLESCRIPT_STORE", &runtime_path)
            .output()
            .expect("whip")
    };
    fixture.write("listing.json", &executor_report(json!([])));

    // Any command but `buck2 test <targets>` has no adapter.
    let refused = whip(&[
        "infer-support",
        "--check",
        "pytest tests",
        "--cut",
        "cut",
        "--as",
        "owner",
    ]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains(
            "no bundled adapter reports cases for `pytest`; only `buck2 test <targets>` is adapted"
        ),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    // One declaration: the check lists its cases into the template.
    let inferred = success(whip(&[
        "infer-support",
        "--check",
        "buck2 test //:passing",
        "--cut",
        "cut",
        "--as",
        "owner",
    ]));
    assert_eq!(inferred["targets"], json!(["//:passing"]));
    assert_eq!(
        inferred["cases"],
        json!([
            {"id": "root//:passing::parses_empty", "assertion": "verdict", "expected": "pass"},
            {"id": "root//:passing::parses_nested", "assertion": "verdict", "expected": "pass"},
        ])
    );
    let support_contract = inferred["support_contract"].as_str().unwrap();
    fixture.write(
        "fields.json",
        &json!({"name":"parses","proposition":"the parser accepts every listed input","domain":"workspace","subject":"main.py","support_contract":support_contract}),
    );
    let created = fixture.run(&[
        "create",
        "obligation@1",
        "--as",
        "owner",
        "--fields",
        "fields.json",
    ]);
    let requirement = created["result"]["event_id"].as_str().unwrap().to_owned();
    fixture.run(&["transition", &requirement, "accepted", "--as", "owner"]);

    // The run, recorded and published.
    fixture.write(
        "run.json",
        &executor_report(json!([
            case("parses_empty", "pass"),
            case("parses_nested", "pass")
        ])),
    );
    let run_args = [
        "run",
        requirement.as_str(),
        "--cut",
        "cut",
        "--effect",
        "parses-at-cut",
        "--vocabulary",
        "local-observation",
        "--as",
        "owner",
    ];
    let ran = success(whip(&run_args));
    assert_eq!(ran["instance"], "buck2-tests:cut");
    assert_eq!(ran["judgment"]["outcome"], "pass", "{ran}");
    let published = ran["event_id"].as_str().unwrap().to_owned();
    // A retry publishes the run it recorded and runs nothing: a failing
    // report now on disk changes nothing.
    fixture.write(
        "run.json",
        &executor_report(json!([
            case("parses_empty", "pass"),
            case("parses_nested", "fail")
        ])),
    );
    let again = success(whip(&run_args));
    assert_eq!(again["event_id"], json!(published));
    assert_eq!(again["run"], ran["run"]);
    assert_eq!(again["judgment"]["outcome"], "pass");

    // The native host's impact plan recovers the run from its journal and
    // re-judges it: the requirement is supported.
    let host = json!({"protocol":"whipplescript.exec.native-norm-host/v1","endpoint":"unix:///no-query-executor","installed":{"protocol":"whipplescript.exec.native-runtime-image/v1","daemon_id":"fixture-daemon","base_image":format!("sha256:{}", "b".repeat(64)),"image_id":format!("sha256:{}", "c".repeat(64)),"runtime":protected_runtime()}});
    fixture.write("host.json", &host);
    let config = json!({"capability":"observer","roles":[{"vocabulary":requirement_ref,"interpretation":"context"},{"vocabulary":observation_ref,"interpretation":"published_execution"}]});
    let planned = success(
        fixture
            .command(&["impact", "cut", "cut"])
            .env("WHIPPLESCRIPT_STORE", &runtime_path)
            .env(
                "WHIPPLESCRIPT_NATIVE_NORM_RUNTIME",
                fixture.root.join("host.json"),
            )
            .env("WHIPPLESCRIPT_NORM_PLANNING", config.to_string())
            .output()
            .unwrap(),
    );
    assert_eq!(
        planned["plan"]["requirements"][&requirement][0]["work"]["kind"], "supported",
        "{planned}"
    );
    assert_eq!(planned["plan"]["evidence_gaps"], json!({}));

    // The hosted object runs no Buck2: the same publication imported there is
    // an unavailable execution naming Buck2, never support, even when its
    // journal holds the record.
    let transport = UnixSocketTransport::new(fixture.root.join("custody.sock"));
    let key = NormCustodyKey::new(
        "owner".into(),
        CredentialName::new("norm/owner").unwrap(),
        NormCustodyVersion::ImmutableLocal,
        &transport,
    )
    .unwrap();
    let verifier = NormGovernanceVerifier::new(
        vec![NormPrincipalBinding {
            actor: key.actor().clone(),
            verifier: &key,
        }],
        [("worker".into(), "owner".into())].into(),
    )
    .unwrap();
    let ledger = WorkItemStore::open(fixture.root.join("items.sqlite")).unwrap();
    let public = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let public_hex: String = public
        .public_key()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let trust = json!({"bindings":[],"public_bindings":[{"actor":key.actor(),"public_key_hex":public_hex}],"creation_grants":[]}).to_string();
    use whipplescript_store::norm_commands::NormCommandStore;
    let mut do_store = whipplescript_host_do::do_store::test_support::store();
    do_store
        .pin_norm_checkpoint(&ledger.norm_checkpoint().unwrap().unwrap())
        .unwrap();
    do_store
        .import_norm(&ledger.export_events().unwrap(), &verifier)
        .unwrap();
    let native_journal = SqliteStore::open(&runtime_path).unwrap();
    let branches = BranchStore::open(fixture.root.join("branches.sqlite")).unwrap();
    let hosted_plan = |do_store: &whipplescript_host_do::do_store::DoSqliteStore<
        whipplescript_host_do::do_store::test_support::RusqliteDoSql,
    >|
     -> Value {
        let result = whipplescript_host_do::norm_commands::execute_hosted_norm_impact(
            do_store,
            whipplescript_host_do::norm_commands::HostedImpactConfiguration {
                trust: &trust,
                planning: &config.to_string(),
                runtime: &protected_runtime().to_string(),
                time_basis: "hosted-fixture",
            },
            &json!({"protocol":"whipplescript.norm.impact/v1", "command":{"before_cut":"cut","after_cut":"cut"}}).to_string(),
            &|cut| capture_cut(&branches, &content, cut, ArtifactLimits::default()),
            |_| Err("no runtime is installed".into()),
        )
        .unwrap();
        serde_json::from_str::<Value>(&result).unwrap()["result"].clone()
    };
    // Scoped to the one requirement its signed invocation names.
    let unavailable = json!({"kind":"execution_unavailable","reason":BUCK2_UNAVAILABLE,"requirement":requirement});
    let hosted = hosted_plan(&do_store);
    assert_eq!(hosted["plan"]["evidence_gaps"][&published], unavailable);
    assert_eq!(
        hosted["plan"]["requirements"][&requirement][0]["work"]["kind"],
        "verify_evidence"
    );
    assert!(BUCK2_UNAVAILABLE.contains("Buck2"));
    for event in native_journal.list_events("buck2-tests:cut").unwrap() {
        if event.event_type == BUCK2_TESTS_RECORDED {
            do_store
                .append_event(NewEvent {
                    instance_id: "buck2-tests:cut",
                    event_type: BUCK2_TESTS_RECORDED,
                    payload_json: &event.payload_json,
                    source: "kernel",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: None,
                })
                .unwrap();
        }
    }
    let with_record = hosted_plan(&do_store);
    assert_eq!(
        with_record["plan"]["evidence_gaps"][&published],
        unavailable
    );
    assert_eq!(
        with_record["plan"]["requirements"][&requirement][0]["work"]["kind"],
        "verify_evidence"
    );
}

fn protected_runtime() -> Value {
    json!({
        "engine": {"kind": "cpython3147_wasi", "artifact_path": "/opt/reactor.wasm", "artifact_sha256": "a".repeat(64)},
        "executable": "/usr/local/bin/whip",
        "python_version": "3.14.7",
        "environment": "epoch",
    })
}
