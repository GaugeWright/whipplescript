use super::*;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_custody::client::UnixSocketTransport;
use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
use whipplescript_kernel::norm_execution::{fixtures as execution, PreparedNormExecution};
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_store::branches::MAINLINE_BRANCH_ID;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm_artifact::ArtifactLimits;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::workstreams::{WorkstreamStore, Workstreams};
use whipplescript_store::{ScriptCapabilityRegistration, SqliteStore};

const DENYING: &str = "def allow(user): return False";
const ALLOWING: &str = "def allow(user): return True";

/// `whip stream promote` in the fixture's workspace, with the norm host's
/// configuration as the arguments say.
fn promote(fixture: &Fixture, stream: &str, host: Option<(&Value, &std::path::Path)>) -> Output {
    whip(fixture, &["stream", "promote", stream], host)
}

/// One `whip` command against the fixture's host-selected stores.
pub(super) fn whip(
    fixture: &Fixture,
    args: &[&str],
    host: Option<(&Value, &std::path::Path)>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_whip"));
    command
        .current_dir(&fixture.root)
        .env_clear()
        .env(
            "WHIPPLESCRIPT_CUSTODIAN_SOCKET",
            fixture.root.join("custody.sock"),
        )
        .env("WHIPPLESCRIPT_NORM_TRUST", fixture.trust.to_string())
        .env(
            "WHIPPLESCRIPT_ITEMS_STORE",
            fixture.root.join("items.sqlite"),
        )
        .env(
            "WHIPPLESCRIPT_BRANCH_STORE",
            fixture.root.join("branches.sqlite"),
        )
        .env(
            "WHIPPLESCRIPT_VCS_CONTENT_STORE",
            fixture.root.join("content.sqlite"),
        )
        .env(
            "WHIPPLESCRIPT_WORKSTREAM_STORE",
            fixture.root.join("workstreams.sqlite"),
        )
        .env(
            "WHIPPLESCRIPT_COORDINATION_STORE",
            fixture.root.join("coordination.sqlite"),
        )
        .env("WHIPPLESCRIPT_STORE", fixture.root.join("runtime.sqlite"));
    if let Some((planning, runtime_host)) = host {
        command
            .env("WHIPPLESCRIPT_NORM_PLANNING", planning.to_string())
            .env("WHIPPLESCRIPT_NATIVE_NORM_RUNTIME", runtime_host);
    }
    command.args(args).output().expect("whip process")
}

/// A door's structured refusal of a mainline move, with the mainline unmoved.
fn refused_naming(fixture: &Fixture, output: &Output, door: &str, requirement: &str) -> Value {
    assert!(
        !output.status.success(),
        "{door} moved the mainline: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let refused: Value = serde_json::from_slice(&output.stdout).expect("refusal JSON");
    assert_eq!(refused["door"], door);
    assert_eq!(refused["target"], "main");
    assert!(
        refused["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(requirement)),
        "{refused}"
    );
    assert_eq!(
        main_file(fixture).as_deref(),
        Some("def allow(user): return None"),
        "a refused {door} leaves the mainline where it was"
    );
    refused
}

fn main_file(fixture: &Fixture) -> Option<String> {
    NativeWorkspaceVcs::open(
        fixture.root.join("branches.sqlite"),
        fixture.root.join("content.sqlite"),
    )
    .expect("the fixture's own step")
    .read(MAINLINE_BRANCH_ID, "main.py")
    .expect("the fixture's own step")
}

/// The mainline gate at the native promote door (norm-plane §5, NP-15): a
/// governed workspace promotes a stream only when the gated requirement is
/// supported at the exact merged result, and otherwise the mainline stays
/// where it was and the refusal names the requirement.
#[test]
fn stream_promotion_passes_the_mainline_gate_only_with_support_at_the_merged_result() {
    for actual in [false, true] {
        let fixture = Fixture::new();
        // The workspace: Main holds a base; the stream's line holds the
        // candidate the evidence is about. Bootstrapping the ledger then
        // leases the mainline to its gate, after which only doors move it.
        let mut vcs = NativeWorkspaceVcs::open(
            fixture.root.join("branches.sqlite"),
            fixture.root.join("content.sqlite"),
        )
        .unwrap();
        vcs.init("t0").unwrap();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "main.py",
            Some("def allow(user): return None"),
            "cut_0",
            "t1",
        )
        .unwrap();
        vcs.create_branch("line-triage", None, MAINLINE_BRANCH_ID, "t2")
            .unwrap();
        vcs.write(
            "line-triage",
            "main.py",
            Some(if actual { ALLOWING } else { DENYING }),
            "cut_1",
            "t3",
        )
        .unwrap();
        WorkstreamStore::open(fixture.root.join("workstreams.sqlite"))
            .unwrap()
            .create_stream("triage", None, "line-triage", "t3", None)
            .unwrap();

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
        let requirement = created["result"]["event_id"].as_str().unwrap().to_owned();
        fixture.run(&["transition", &requirement, "accepted", "--as", "owner"]);

        // The host: an installed observer, the protected runtime, and how to
        // read the ledger's vocabularies.
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
        SqliteStore::open(&runtime_path)
            .unwrap()
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
        let planning = json!({"capability":"observer","roles":[{"vocabulary":requirement_ref,"interpretation":"context"},{"vocabulary":observation_ref,"interpretation":"published_execution"}]});
        let host_path = fixture.root.join("host.json");

        // A host that holds a ledger but cannot evaluate it refuses, naming
        // what it lacks, and the mainline stays.
        let blind = promote(&fixture, "triage", None);
        assert!(!blind.status.success());
        let refused: Value = serde_json::from_slice(&blind.stdout).expect("refusal JSON");
        assert_eq!(
            refused["reason"],
            "the mainline's gated requirements cannot be evaluated: host must configure WHIPPLESCRIPT_NORM_PLANNING"
        );
        assert_eq!(
            main_file(&fixture).as_deref(),
            Some("def allow(user): return None")
        );

        // Evidence for the line's exact content, through the verified
        // execution and publication path.
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
        let history = CapturedNormHistory::capture(
            &view,
            &ledger.export_events().unwrap(),
            &verifier,
            NormHistoryLimits::default(),
        )
        .unwrap();
        let artifact = vcs
            .capture_norm_artifact("cut_1", ArtifactLimits::default())
            .unwrap();
        let prepared = PreparedNormExecution::prepare(
            &history,
            &verifier,
            &artifact,
            &installed,
            execution::selection(&view.ledger, &requirement),
        )
        .unwrap();
        drop(execution::journal_execution(
            SqliteStore::open(&runtime_path).unwrap(),
            &prepared,
            &execution::receipt(&prepared, actual, false),
            actual,
        ));
        let published = fixture
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
            .unwrap();
        assert!(
            published.status.success(),
            "{}",
            String::from_utf8_lossy(&published.stderr)
        );
        drop(vcs);

        let output = promote(&fixture, "triage", Some((&planning, &host_path)));
        if actual {
            // The candidate fails its requirement: refused by name, with the
            // work its support needs, and the mainline unmoved.
            assert!(!output.status.success());
            let refused: Value = serde_json::from_slice(&output.stdout).expect("refusal JSON");
            assert_eq!(refused["refused"], "triage");
            assert_eq!(
                refused["detail"]["requirements"][&requirement],
                json!(["repair"])
            );
            assert_eq!(
                refused["reason"],
                format!("the proposed result is not supported: {requirement} (repair)")
            );
            assert_eq!(
                main_file(&fixture).as_deref(),
                Some("def allow(user): return None"),
                "a refused promotion leaves the mainline where it was"
            );
            // The same result through every other door onto the mainline
            // asks the same predicate and refuses with the requirement named
            // (NP-15): a transport onto mainline, a restore to the line's cut,
            // and an operator undo of the mainline's own write.
            let host = Some((&planning, host_path.as_path()));
            let transported = refused_naming(
                &fixture,
                &whip(
                    &fixture,
                    &[
                        "--json",
                        "branch",
                        "transport",
                        "line-triage",
                        "path(main.py)",
                        "--onto",
                        "main",
                        "--apply",
                    ],
                    host,
                ),
                "transport",
                &requirement,
            );
            assert_eq!(
                transported["detail"]["requirements"][&requirement],
                json!(["repair"])
            );
            refused_naming(
                &fixture,
                &whip(
                    &fixture,
                    &["--json", "branch", "restore", "main", "cut_1"],
                    host,
                ),
                "restore",
                &requirement,
            );
            refused_naming(
                &fixture,
                &whip(&fixture, &["--json", "branch", "undo-op", "op-cut_0"], host),
                "undo-op",
                &requirement,
            );
        } else {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(main_file(&fixture).as_deref(), Some(DENYING));
            // A governed mainline moves only through doors: the store refuses
            // a plain write under the gate's lease.
            let written = whip(
                &fixture,
                &["branch", "write", "main", "main.py", "--body", ALLOWING],
                Some((&planning, &host_path)),
            );
            assert!(!written.status.success());
            assert!(
                String::from_utf8_lossy(&written.stderr).contains("reserved by `norm-gate`"),
                "{}",
                String::from_utf8_lossy(&written.stderr)
            );
            assert_eq!(main_file(&fixture).as_deref(), Some(DENYING));
        }
    }
}
