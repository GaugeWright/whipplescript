use super::*;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_custody::client::UnixSocketTransport;
use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
use whipplescript_kernel::norm_execution::{fixtures as execution, PreparedNormExecution};
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
use whipplescript_store::content::ContentStore;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::{ScriptCapabilityRegistration, SqliteStore};

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("impact JSON")
}
#[test]
fn norm_cli_impact_uses_host_installation_and_recovered_publications() {
    let mut hosted_vectors = Vec::new();
    for actual in [false, true] {
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
        let mut method = execution::method();
        method.runtime.engine = whipplescript_kernel::norm_runner::PythonEngine::Cpython3147Wasi {
            artifact_path: "/opt/reactor.wasm".into(),
            artifact_sha256: "a".repeat(64),
        };
        method.runtime.executable = "/usr/local/bin/whip".into();
        let mut support = execution::template();
        support["method"] = json!(method);
        fixture.write("fields.json", &json!({"name":"allow","proposition":"unknown denied","domain":"workspace","subject":"main.py","support_contract":support.to_string()}));
        let created = fixture.run(&[
            "create",
            "obligation@1",
            "--as",
            "owner",
            "--fields",
            "fields.json",
        ]);
        let requirement = created["result"]["event_id"].as_str().unwrap();
        fixture.run(&["transition", requirement, "accepted", "--as", "owner"]);
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
        let view = ledger.norm_view(&verifier).unwrap();
        fixture.write("before-frontier.json", &json!(view.frontier));
        let history = CapturedNormHistory::capture(
            &view,
            &ledger.export_events().unwrap(),
            &verifier,
            NormHistoryLimits::default(),
        )
        .unwrap();
        let mut branches = BranchStore::open(fixture.root.join("branches.sqlite")).unwrap();
        let content = ContentStore::open(fixture.root.join("content.sqlite")).unwrap();
        branches.ensure_mainline("t0").unwrap();
        let file = content
            .put(
                if actual {
                    "def allow(user): return True"
                } else {
                    "def allow(user): return False"
                }
                .as_bytes(),
            )
            .unwrap();
        let manifest = content
            .put(json!({"main.py":file}).to_string().as_bytes())
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
        branches
            .record_cut(CutRecord {
                cut_id: "same-content",
                change_id: "same-content",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: &manifest,
                parent_cut_id: None,
                origin: None,
                actor: None,
                intent: None,
                recorded_at: "t1",
            })
            .unwrap();
        let artifact = capture_cut(&branches, &content, "cut", ArtifactLimits::default()).unwrap();
        let mut installed = execution::script();
        installed.body = method.adapter().into();
        installed.sha256 = whipplescript_kernel::exec_http::sha256_hex(installed.body.as_bytes());
        installed.argv_json = json!([
            method.runtime.executable,
            "executor",
            "observe-norm",
            "{script}"
        ])
        .to_string();
        let runtime_path = fixture.root.join("runtime.sqlite");
        let runtime = SqliteStore::open(&runtime_path).unwrap();
        runtime
            .register_script_capability(ScriptCapabilityRegistration {
                name: &installed.name,
                argv_json: &installed.argv_json,
                sha256: &installed.sha256,
                env_json: &installed.env_json,
                hermetic: false,
                body: &installed.body,
            })
            .unwrap();
        let host = json!({"protocol":"whipplescript.exec.native-norm-host/v1","endpoint":"unix:///no-query-executor","installed":{"protocol":"whipplescript.exec.native-runtime-image/v1","daemon_id":"fixture-daemon","base_image":format!("sha256:{}", "b".repeat(64)),"image_id":format!("sha256:{}", "c".repeat(64)),"runtime":method.runtime}});
        fixture.write("host.json", &host);
        let config = json!({"capability":"observer","roles":[{"vocabulary":requirement_ref,"interpretation":"context"},{"vocabulary":observation_ref,"interpretation":"published_execution"}]});
        let invoke = |args: &[&str], config: &Value, host: &str| {
            fixture
                .command(args)
                .env("WHIPPLESCRIPT_STORE", &runtime_path)
                .env("WHIPPLESCRIPT_NATIVE_NORM_RUNTIME", fixture.root.join(host))
                .env("WHIPPLESCRIPT_NORM_PLANNING", config.to_string())
                .output()
                .expect("impact process")
        };
        let initial = success(invoke(&["impact", "cut", "cut"], &config, "host.json"));
        assert_eq!(
            initial["plan"]["requirements"][requirement][0]["work"]["kind"],
            "check"
        );
        assert!(initial["method_gaps"].as_object().unwrap().is_empty());
        let mut missing_capability = config.clone();
        missing_capability["capability"] = json!("missing");
        let missing = success(invoke(
            &["impact", "cut", "cut"],
            &missing_capability,
            "host.json",
        ));
        assert_eq!(
            missing["plan"]["requirements"][requirement][0]["work"]["kind"],
            "observation_gap"
        );
        assert!(missing["method_gaps"][requirement][0]["reason"]
            .as_str()
            .unwrap()
            .contains("not registered"));
        let mut other_host = host.clone();
        other_host["installed"]["runtime"]["environment"] = json!("different-runtime");
        fixture.write("other-host.json", &other_host);
        let other = success(invoke(
            &["impact", "cut", "cut"],
            &config,
            "other-host.json",
        ));
        assert_eq!(
            other["plan"]["requirements"][requirement][0]["work"]["kind"],
            "observation_gap"
        );
        assert!(other["method_gaps"][requirement][0]["reason"]
            .as_str()
            .unwrap()
            .contains("installed profile"));
        for fault in ["duplicate", "empty", "unknown-field", "capability"] {
            let mut changed = config.clone();
            match fault {
                "duplicate" => {
                    let role = changed["roles"][0].clone();
                    changed["roles"].as_array_mut().unwrap().push(role);
                }
                "empty" => changed["roles"][0]["vocabulary"]["digest"] = json!(""),
                "unknown-field" => changed["caller_permission"] = json!(true),
                _ => changed["capability"] = json!(""),
            }
            assert!(
                !invoke(&["impact", "cut", "cut"], &changed, "host.json")
                    .status
                    .success(),
                "{fault}"
            );
        }
        assert!(!invoke(&["impact", "cut", "missing"], &config, "host.json")
            .status
            .success());
        assert!(!invoke(
            &["impact", "cut", "cut", "--capability", "caller"],
            &config,
            "host.json"
        )
        .status
        .success());
        assert!(!fixture
            .command(&["impact", "cut", "cut"])
            .output()
            .unwrap()
            .status
            .success());
        // Authenticated executor transport fixture, not a live interpreter.
        let prepared = PreparedNormExecution::prepare(
            &history,
            &verifier,
            &artifact,
            &installed,
            execution::selection(&view.ledger, requirement),
        )
        .unwrap();
        drop(execution::journal_execution(
            SqliteStore::open(&runtime_path).unwrap(),
            &prepared,
            &execution::receipt(&prepared, actual, false),
            actual,
        ));
        success(
            fixture
                .command(&[
                    "publish-observation",
                    "instance",
                    "run",
                    "local-observation@1",
                    "--as",
                    "owner",
                ])
                .env("WHIPPLESCRIPT_STORE", &runtime_path)
                .output()
                .unwrap(),
        );
        {
            use ring::signature::KeyPair;
            use whipplescript_host_do::norm_commands::{
                execute_hosted_norm_impact, HostedImpactConfiguration,
            };
            use whipplescript_store::norm_commands::NormCommandStore;
            use whipplescript_store::RuntimeStore;
            let public = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
            let public_hex: String = public
                .public_key()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let trust = json!({"bindings":[],"public_bindings":[{"actor":key.actor(),"public_key_hex":public_hex}],"creation_grants":[]}).to_string();
            let mut do_store = whipplescript_host_do::do_store::test_support::store();
            do_store
                .pin_norm_checkpoint(&ledger.norm_checkpoint().unwrap().unwrap())
                .unwrap();
            do_store
                .import_norm(&ledger.export_events().unwrap(), &verifier)
                .unwrap();
            do_store
                .register_script_capability(ScriptCapabilityRegistration {
                    name: &installed.name,
                    argv_json: &installed.argv_json,
                    sha256: &installed.sha256,
                    env_json: &installed.env_json,
                    hermetic: false,
                    body: &installed.body,
                })
                .unwrap();
            let hosted = execution::journal_execution(
                do_store,
                &prepared,
                &execution::receipt(&prepared, actual, false),
                actual,
            );
            let planning = config.to_string();
            let runtime_config = json!(method.runtime).to_string();
            let request = json!({"protocol":"whipplescript.norm.impact/v1", "command":{"before_cut":"cut","after_cut":"cut"}});
            let image = format!("sha256:{}", "c".repeat(64));
            let deployment = json!({"planning":planning,"runtime":runtime_config,"deployed_image":image,
                "image_binding":json!({"protocol":"whipplescript.exec.runtime-image/v1","image_id":image,"runtime":method.runtime}).to_string(), "time_basis":"hosted-fixture"});
            let installed_query = |deployment: &Value| {
                whipplescript_host_do::norm_commands::execute_installed_hosted_norm_impact(
                    hosted.store(),
                    &trust,
                    &request.to_string(),
                    &|cut| capture_cut(&branches, &content, cut, ArtifactLimits::default()),
                    &deployment.to_string(),
                )
            };
            let expected: Value =
                serde_json::from_str(&installed_query(&deployment).unwrap()).unwrap();
            let mut bounded = deployment.to_string();
            bounded.push_str(&" ".repeat(131_072 - bounded.len()));
            let query_wire = |wire: &str| {
                whipplescript_host_do::norm_commands::execute_installed_hosted_norm_impact(
                    hosted.store(),
                    &trust,
                    &request.to_string(),
                    &|cut| capture_cut(&branches, &content, cut, ArtifactLimits::default()),
                    wire,
                )
            };
            assert!(query_wire(&bounded).is_ok());
            assert!(query_wire(&(bounded + " ")).is_err());

            for field in [
                "deployed_image",
                "runtime",
                "image_binding",
                "time_basis",
                "planning",
                "extra",
            ] {
                let mut bad = deployment.clone();
                bad[field] = json!("wrong");
                // A nonempty host time is valid; a blank time must refuse.
                if field == "time_basis" {
                    bad[field] = json!("");
                }
                assert!(installed_query(&bad).is_err(), "{field}");
            }
            {
                use whipplescript_host_do::do_store::{DoSql, SqlValue};
                let mut runtime_rows = Vec::new();
                for table in hosted.store().sql.query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY CASE WHEN name = 'instances' THEN 0 ELSE 1 END, name", &[]).unwrap() {
                    let SqlValue::Text(table) = &table[0] else { panic!("table name") };
                    let columns: Vec<String> = hosted.store().sql.query(&format!("PRAGMA table_info(\"{table}\")"), &[]).unwrap().into_iter().map(|row| match &row[1] { SqlValue::Text(name) => name.clone(), _ => panic!("column name") }).collect();
                    if !columns.iter().any(|name| name == "instance_id") && table != "script_capabilities" { continue; }
                    let rows: Vec<Value> = hosted.store().sql.query(&format!("SELECT * FROM \"{table}\""), &[]).unwrap().iter().map(|row| json!(row.iter().map(|value| match value { SqlValue::Null => Value::Null, SqlValue::Int(n) => json!(n), SqlValue::Text(s) => json!(s) }).collect::<Vec<_>>())).collect();
                    if !rows.is_empty() { runtime_rows.push(json!({"table":table,"columns":columns,"rows":rows})); }
                }
                let source = if actual {
                    "def allow(user): return True"
                } else {
                    "def allow(user): return False"
                };
                hosted_vectors.push(json!({"trust":serde_json::from_str::<Value>(&trust).unwrap(),"checkpoint":ledger.norm_checkpoint().unwrap().unwrap(),"events":ledger.export_events().unwrap(),"runtime_rows":runtime_rows,"deployment":deployment,"request":request,"expected":expected,"requirement":requirement,"old_frontier":view.frontier,
                    "artifacts":{"blobs":[{"id":file,"body":source,"byte_len":source.len()},{"id":manifest,"body":json!({"main.py":file}).to_string(),"byte_len":json!({"main.py":file}).to_string().len()}],"cuts":[{"cut_id":"cut","change_id":"cut","branch_id":MAINLINE_BRANCH_ID,"manifest_hash":manifest,"recorded_at":"t0"},{"cut_id":"same-content","change_id":"same-content","branch_id":MAINLINE_BRANCH_ID,"manifest_hash":manifest,"recorded_at":"t1"}]}}));
            }
            let events_before = hosted.store().list_events("instance").unwrap();
            let invoke_hosted = |request: &Value, trust: &str| {
                execute_hosted_norm_impact(
                    hosted.store(),
                    HostedImpactConfiguration {
                        trust,
                        planning: &planning,
                        runtime: &runtime_config,
                        time_basis: "hosted-fixture",
                    },
                    &request.to_string(),
                    &|cut| capture_cut(&branches, &content, cut, ArtifactLimits::default()),
                    |_| Err("fixture has no installed runtime".into()),
                )
            };
            let result: Value =
                serde_json::from_str(&invoke_hosted(&request, &trust).unwrap()).unwrap();
            assert_eq!(result["protocol"], "whipplescript.norm.impact/v1");
            assert_eq!(
                result["result"]["plan"]["requirements"][requirement][0]["work"]["kind"],
                if actual { "repair" } else { "supported" }
            );
            assert_eq!(result["result"]["plan"]["time_basis"], "hosted-fixture");
            let mut old = request.clone();
            old["command"]["before_frontier"] = json!(view.frontier);
            old["command"]["after_frontier"] = json!(view.frontier);
            let result: Value =
                serde_json::from_str(&invoke_hosted(&old, &trust).unwrap()).unwrap();
            assert_eq!(
                result["result"]["plan"]["requirements"][requirement][0]["work"]["kind"],
                "observation_gap"
            );
            assert_eq!(result["result"]["before_frontier"], json!(view.frontier));
            assert_eq!(result["result"]["after_frontier"], json!(view.frontier));
            assert!(result["result"]["method_gaps"]
                .to_string()
                .contains("fixture has no installed runtime"));
            let installed_plan: Value = serde_json::from_str(
                &execute_hosted_norm_impact(
                    hosted.store(),
                    HostedImpactConfiguration {
                        trust: &trust,
                        planning: &planning,
                        runtime: &runtime_config,
                        time_basis: "hosted-fixture",
                    },
                    &old.to_string(),
                    &|cut| capture_cut(&branches, &content, cut, ArtifactLimits::default()),
                    |selected| {
                        if selected == &method.runtime {
                            Ok(())
                        } else {
                            Err("fixture runtime differs".into())
                        }
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                installed_plan["result"]["plan"]["requirements"][requirement][0]["work"]["kind"],
                "check"
            );
            for (field, value) in [
                ("protocol", json!("wrong")),
                ("trust", json!({})),
                ("planning", config.clone()),
                ("runtime", json!(method.runtime)),
                ("time_basis", json!("caller")),
            ] {
                let mut bad = request.clone();
                bad[field] = value;
                assert!(invoke_hosted(&bad, &trust).is_err(), "{field}");
            }
            for field in [
                "policy",
                "capability",
                "artifacts",
                "installation",
                "time_basis",
            ] {
                let mut bad = request.clone();
                bad["command"][field] = json!("caller");
                assert!(invoke_hosted(&bad, &trust).is_err(), "{field}");
            }
            let mut bad = request.clone();
            bad["command"]["after_cut"] = json!("missing");
            assert!(invoke_hosted(&bad, &trust).is_err());
            assert!(invoke_hosted(&request, r#"{"bindings":[],"creation_grants":[]}"#).is_err());
            assert_eq!(
                hosted.store().list_events("instance").unwrap(),
                events_before
            );
        }
        let ledger_before = ledger.export_events().unwrap();
        let journal_before = runtime.list_events("instance").unwrap();
        let runs_before = runtime.list_runs("instance").unwrap();
        for _ in 0..2 {
            let planned = success(invoke(&["impact", "cut", "cut"], &config, "host.json"));
            assert_eq!(
                planned["plan"]["requirements"][requirement][0]["work"]["kind"],
                if actual { "repair" } else { "supported" }
            );
            assert!(planned["plan"]["evidence_gaps"]
                .as_object()
                .unwrap()
                .is_empty());
            assert!(planned["plan"]["time_basis"]
                .as_str()
                .unwrap()
                .starts_with("native-impact/"));
        }
        let old = success(invoke(
            &[
                "impact",
                "cut",
                "cut",
                "--before-frontier",
                "before-frontier.json",
                "--after-frontier",
                "before-frontier.json",
            ],
            &config,
            "host.json",
        ));
        assert_eq!(
            old["plan"]["requirements"][requirement][0]["work"]["kind"],
            "check"
        );
        let mut unknown = config.clone();
        unknown["roles"].as_array_mut().unwrap().pop();
        let unknown = success(invoke(&["impact", "cut", "cut"], &unknown, "host.json"));
        assert_eq!(
            unknown["plan"]["requirements"][requirement][0]["work"]["kind"],
            "verify_evidence"
        );
        assert_eq!(ledger.export_events().unwrap(), ledger_before);
        assert_eq!(runtime.list_events("instance").unwrap(), journal_before);
        assert_eq!(runtime.list_runs("instance").unwrap(), runs_before);
        assert!(
            !invoke(&["impact", "cut", "cut"], &config, "missing-host.json")
                .status
                .success()
        );
        // Another cut with the same candidate bytes cannot replace the run's
        // original source capture when independently recovering publication.
        rusqlite::Connection::open(fixture.root.join("branches.sqlite"))
            .unwrap()
            .execute("DELETE FROM cuts WHERE cut_id = 'cut'", [])
            .unwrap();
        let unavailable = success(invoke(
            &["impact", "same-content", "same-content"],
            &config,
            "host.json",
        ));
        assert_eq!(
            unavailable["plan"]["requirements"][requirement][0]["work"]["kind"],
            "verify_evidence"
        );
        assert_eq!(
            unavailable["plan"]["evidence_gaps"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(ledger.export_events().unwrap(), ledger_before);
        assert_eq!(runtime.list_events("instance").unwrap(), journal_before);
        assert_eq!(runtime.list_runs("instance").unwrap(), runs_before);
    }
    if let Ok(path) = std::env::var("WHIPPLESCRIPT_NORM_IMPACT_VECTOR_OUT") {
        std::fs::write(
            path,
            json!({"protocol":"whipplescript.norm.impact-test-vector/v1", "cases":hosted_vectors})
                .to_string(),
        )
        .unwrap();
    }
}

#[test]
fn norm_shared_impact_recovers_native_and_do_journals_identically() {
    use whipplescript_kernel::norm_execution_policy::ProtectedPythonPolicy;
    use whipplescript_kernel::norm_planning::{execute, ImpactQuery, PlanningConfiguration};
    use whipplescript_kernel::norm_publication::{
        ObservationSigning, PreparedObservationPublication,
    };
    use whipplescript_store::RuntimeStore;

    for actual in [false, true] {
        let mut method = execution::method();
        method.runtime.engine = whipplescript_kernel::norm_runner::PythonEngine::Cpython3147Wasi {
            artifact_path: "/opt/reactor.wasm".into(),
            artifact_sha256: "a".repeat(64),
        };
        method.runtime.executable = "whip".into();
        let mut support = execution::template();
        support["method"] = json!(method);
        let (mut ledger, requirement) =
            execution::fixture_with_observation(Some(support), true, true);
        let before = execution::history(&ledger);
        let source = execution::artifact("def allow(user): return False");
        let mut installed = execution::script();
        installed.body = method.adapter().into();
        installed.sha256 = whipplescript_kernel::exec_http::sha256_hex(installed.body.as_bytes());
        installed.argv_json = json!(["whip", "executor", "observe-norm", "{script}"]).to_string();
        let prepared = PreparedNormExecution::prepare(
            &before,
            &execution::Boundary,
            &source,
            &installed,
            execution::selection(&before.anchor().checkpoint.ledger, &requirement),
        )
        .unwrap();
        let receipt = execution::receipt(&prepared, actual, false);
        let native = execution::journal_execution(
            SqliteStore::open_in_memory().unwrap(),
            &prepared,
            &receipt,
            actual,
        );
        let hosted = execution::journal_execution(
            whipplescript_host_do::do_store::test_support::store(),
            &prepared,
            &receipt,
            actual,
        );
        let verified = prepared
            .verify_settled(native.store(), "instance", "run")
            .unwrap();
        let vocabulary = Vocabulary::new(execution::observation_vocabulary().definition)
            .unwrap()
            .reference()
            .clone();
        let publication = PreparedObservationPublication::prepare(
            &verified,
            &before,
            native.store(),
            &execution::Boundary,
            ObservationSigning {
                vocabulary: &vocabulary,
                authority: None,
                actor: &execution::actor(),
                created_at: "t1",
            },
            |statement| {
                Ok(whipplescript_kernel::exec_http::sha256_hex(
                    &statement.signing_bytes().unwrap(),
                ))
            },
        )
        .unwrap();
        publication
            .submit(&mut ledger, &execution::Boundary)
            .unwrap();
        let current = execution::history(&ledger);
        let requirement_vocabulary = ledger.norm_view(&execution::Boundary).unwrap().records
            [&requirement]
            .vocabulary
            .clone();
        let configuration = PlanningConfiguration::parse(
            &json!({"capability":"observer", "roles":[
                {"vocabulary":requirement_vocabulary,"interpretation":"context"},
                {"vocabulary":vocabulary,"interpretation":"published_execution"}
            ]})
            .to_string(),
        )
        .unwrap();
        let policy =
            ProtectedPythonPolicy::new(&json!(method.runtime).to_string(), "parity-capture")
                .unwrap();
        let native_events = native.store().list_events("instance").unwrap();
        let hosted_events = hosted.store().list_events("instance").unwrap();
        for missing_original in [false, true] {
            let artifacts = |cut: &str| {
                if missing_original || cut != "cut" {
                    return Err(whipplescript_store::StoreError::Conflict(
                        "original cut unavailable".into(),
                    ));
                }
                Ok(execution::artifact("def allow(user): return False"))
            };
            // Keep candidate capture available while independently refusing only
            // recovery's original cut. Equal bytes cannot substitute its identity.
            let captures = |cut: &str| {
                if cut == "candidate" {
                    Ok(execution::artifact_at(
                        "def allow(user): return False",
                        "candidate",
                    ))
                } else {
                    artifacts(cut)
                }
            };
            let query = |runtime| ImpactQuery {
                configuration: &configuration,
                history: &current,
                verifier: &execution::Boundary,
                runtime,
                artifacts: &captures,
                before_cut: "candidate",
                after_cut: "candidate",
                before_frontier: None,
                after_frontier: None,
                policy: &policy,
            };
            let left = execute(query(native.store()), |_| {
                Err("discovery must not replace recovered evidence".into())
            })
            .unwrap();
            let right = execute(
                ImpactQuery {
                    configuration: &configuration,
                    history: &current,
                    verifier: &execution::Boundary,
                    runtime: hosted.store(),
                    artifacts: &captures,
                    before_cut: "candidate",
                    after_cut: "candidate",
                    before_frontier: None,
                    after_frontier: None,
                    policy: &policy,
                },
                |_| Err("discovery must not replace recovered evidence".into()),
            )
            .unwrap();
            assert_eq!(left, right);
            let expected = if missing_original {
                "verify_evidence"
            } else if actual {
                "repair"
            } else {
                "supported"
            };
            assert_eq!(
                left["plan"]["requirements"][&requirement][0]["work"]["kind"], expected,
                "{left}"
            );
        }
        assert_eq!(
            native.store().list_events("instance").unwrap(),
            native_events
        );
        assert_eq!(
            hosted.store().list_events("instance").unwrap(),
            hosted_events
        );
    }
}
