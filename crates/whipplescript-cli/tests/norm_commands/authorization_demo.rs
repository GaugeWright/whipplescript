//! The first admission loop over `examples/authorization-demo` (norm-plane
//! admission fixture, S1): NP-19's repair admitted under a current token, the
//! stale token of NP-20 refused, and NP-22's historical folding kept while
//! current conformance goes stale and then contradicted.

use super::admission::whip;
use super::*;
use std::collections::BTreeMap;
use whipplescript_core::norm_evidence::RequiredCase;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_custody::client::UnixSocketTransport;
use whipplescript_host_do::do_store::test_support::RusqliteDoSql;
use whipplescript_host_do::do_store::DoSqliteStore;
use whipplescript_host_do::norm_commands::execute_hosted_norm_command_with_artifacts;
use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
use whipplescript_kernel::norm_execution::{
    fixtures as execution, NormRunSelection, PreparedNormExecution, PythonCallSupport,
};
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_kernel::norm_runner::{PythonCallMethod, PythonCase, PythonEngine};
use whipplescript_store::branches::MAINLINE_BRANCH_ID;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::{NormCharter, NormView};
use whipplescript_store::norm_artifact::ArtifactLimits;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::workstreams::{WorkstreamStore, Workstreams};
use whipplescript_store::{RuntimeStore, ScriptCapabilityRegistration, SqliteStore};

const REQUIREMENT: &str = "custody-authorization";
const MUTATED: &str = "def grant_allows(grant):\n    return grant in (\"allow\", \"deny\")\n";
const REPAIRED: &str =
    "def grant_allows(grant):\n    # Only an explicit allowing grant allows.\n    return grant == \"allow\"\n";

/// A file of the checked-in demo workspace, embedded so every build of this
/// test reads exactly the committed demo.
fn demo(path: &str) -> String {
    match path {
        "charter.json" => include_str!("../../../../examples/authorization-demo/charter.json"),
        "checks/q0.json" => include_str!("../../../../examples/authorization-demo/checks/q0.json"),
        "src/auth.py" => include_str!("../../../../examples/authorization-demo/src/auth.py"),
        "src/parser.py" => include_str!("../../../../examples/authorization-demo/src/parser.py"),
        other => panic!("the demo has no {other}"),
    }
    .to_owned()
}

/// Q0, the demo's four-case check, over the host's runtime: the method the
/// runner calls and the cases the requirement installs.
fn q0(method: &PythonCallMethod) -> (PythonCallMethod, Vec<RequiredCase>) {
    let q0: Value = serde_json::from_str(&demo("checks/q0.json")).expect("Q0");
    let cases = q0["cases"].as_array().expect("Q0 cases");
    let method = PythonCallMethod {
        runtime: method.runtime.clone(),
        module: q0["module"].as_str().expect("module").into(),
        function: q0["function"].as_str().expect("function").into(),
        cases: cases
            .iter()
            .map(|case| PythonCase {
                id: case["id"].as_str().expect("id").into(),
                args: vec![case["role"].clone(), case["grant"].clone()],
                kwargs: BTreeMap::new(),
            })
            .collect(),
    };
    let required = cases
        .iter()
        .map(|case| RequiredCase {
            id: case["id"].as_str().expect("id").into(),
            assertion: format!(
                "authorize({}, {}) is {}",
                case["role"].as_str().expect("role"),
                case["grant"].as_str().expect("grant"),
                case["expected"]
            ),
            expected: case["expected"].clone(),
        })
        .collect();
    (method, required)
}

/// The demo's host: the protected runtime, the installed observer, and how
/// to read every vocabulary of C0.
struct Host {
    planning: Value,
    path: std::path::PathBuf,
    installed: whipplescript_store::ScriptCapabilityRecord,
    required: Vec<RequiredCase>,
    /// R0's support contract: Q0 over this host's runtime.
    support: String,
    runtime: whipplescript_kernel::norm_runner::PythonRuntime,
}

impl Host {
    fn install(fixture: &Fixture, charter: &NormCharter) -> Self {
        let mut method = execution::method();
        method.runtime.engine = PythonEngine::Cpython3147Wasi {
            artifact_path: "/opt/reactor.wasm".into(),
            artifact_sha256: "a".repeat(64),
        };
        method.runtime.executable = "/usr/local/bin/whip".into();
        let (method, required) = q0(&method);
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
        SqliteStore::open(fixture.root.join("runtime.sqlite"))
            .expect("runtime")
            .register_script_capability(ScriptCapabilityRegistration {
                name: &installed.name,
                argv_json: &installed.argv_json,
                sha256: &installed.sha256,
                env_json: &installed.env_json,
                hermetic: false,
                body: &installed.body,
            })
            .expect("observer");
        fixture.write("host.json", &json!({"protocol":"whipplescript.exec.native-norm-host/v1","endpoint":"unix:///no-query-executor","installed":{"protocol":"whipplescript.exec.native-runtime-image/v1","daemon_id":"fixture-daemon","base_image":format!("sha256:{}", "b".repeat(64)),"image_id":format!("sha256:{}", "c".repeat(64)),"runtime":method.runtime}}));
        let roles: Vec<Value> = charter
            .vocabularies
            .iter()
            .map(|entry| {
                let interpretation = match entry.definition.name.as_str() {
                    "local-observation" => "published_execution",
                    "reservation" => "reservation",
                    _ => "context",
                };
                json!({
                    "vocabulary": Vocabulary::new(entry.definition.clone()).expect("C0").reference(),
                    "interpretation": interpretation,
                })
            })
            .collect();
        let runtime = method.runtime.clone();
        let support = json!(PythonCallSupport::V1 {
            method,
            cases: required.clone(),
        })
        .to_string();
        Self {
            planning: json!({"capability": "observer", "roles": roles}),
            path: fixture.root.join("host.json"),
            installed,
            required,
            support,
            runtime,
        }
    }

    fn configured(&self) -> Option<(&Value, &std::path::Path)> {
        Some((&self.planning, &self.path))
    }
}

/// The ledger as the fixture's principals signed it, read in process.
fn with_view<T>(
    fixture: &Fixture,
    read: impl FnOnce(&WorkItemStore, &NormView, &dyn whipplescript_store::norm::NormVerifier) -> T,
) -> T {
    let transport = UnixSocketTransport::new(fixture.root.join("custody.sock"));
    let key = |name: &str| {
        NormCustodyKey::new(
            name.into(),
            CredentialName::new(&format!("norm/{name}")).expect("credential"),
            NormCustodyVersion::ImmutableLocal,
            &transport,
        )
        .expect("custody key")
    };
    let (owner, worker) = (key("owner"), key("worker"));
    let verifier = NormGovernanceVerifier::new(
        vec![
            NormPrincipalBinding {
                actor: owner.actor().clone(),
                verifier: &owner,
            },
            NormPrincipalBinding {
                actor: worker.actor().clone(),
                verifier: &worker,
            },
        ],
        [("worker".into(), "owner".into())].into(),
    )
    .expect("verifier");
    let ledger = WorkItemStore::open(fixture.root.join("items.sqlite")).expect("ledger");
    let view = ledger.norm_view(&verifier).expect("verified view");
    read(&ledger, &view, &verifier)
}

/// Run Q0 on a stored cut through the verified execution path and publish
/// what it observed. `wrong` names the cases whose returned value is the
/// opposite of what the requirement expects.
fn observe(
    fixture: &Fixture,
    host: &Host,
    hosted: &Hosted,
    requirement: &str,
    cut: &str,
    run: &str,
    wrong: &[&str],
) {
    let prepared = with_view(fixture, |ledger, view, verifier| {
        let history = CapturedNormHistory::capture(
            view,
            &ledger.export_events().expect("history"),
            verifier,
            NormHistoryLimits::default(),
        )
        .expect("history");
        let artifact = NativeWorkspaceVcs::open(
            fixture.root.join("branches.sqlite"),
            fixture.root.join("content.sqlite"),
        )
        .expect("workspace")
        .capture_norm_artifact(cut, ArtifactLimits::default())
        .expect("candidate");
        let effect = format!("observe-{run}");
        PreparedNormExecution::prepare(
            &history,
            verifier,
            &artifact,
            &host.installed,
            NormRunSelection {
                effect_id: &effect,
                ..execution::selection(&view.ledger, requirement)
            },
        )
        .expect("prepared execution")
    });
    let cases: Vec<(&str, &str, Value)> = host
        .required
        .iter()
        .map(|case| {
            let expected = case.expected.as_bool().expect("boolean case");
            let actual = expected != wrong.contains(&case.id.as_str());
            (case.id.as_str(), case.assertion.as_str(), json!(actual))
        })
        .collect();
    let failed = !wrong.is_empty();
    let receipt = execution::receipt_cases(&prepared, &cases, failed);
    drop(execution::journal_execution_as(
        SqliteStore::open(fixture.root.join("runtime.sqlite")).expect("runtime"),
        &prepared,
        &receipt,
        failed,
        &format!("instance-{run}"),
        &format!("run-{run}"),
    ));
    // The hosted object's journal holds the same settled execution, so its
    // own recovery reconstructs the publication's evidence.
    drop(execution::journal_execution_as(
        DoSqliteStore::new(hosted.sql.clone()),
        &prepared,
        &receipt,
        failed,
        &format!("instance-{run}"),
        &format!("run-{run}"),
    ));
    let published = fixture
        .command(&[
            "publish-observation",
            &format!("instance-{run}"),
            &format!("run-{run}"),
            "local-observation@1",
            "--as",
            "owner",
        ])
        .env("WHIPPLESCRIPT_STORE", fixture.root.join("runtime.sqlite"))
        .output()
        .expect("publication");
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
}

/// The same workspace as a hosted workspace object: its own branches,
/// content and runtime journal, the native ledger imported through the hosted
/// command door under deployment trust, and the hosted doors answering.
struct Hosted {
    sql: RusqliteDoSql,
    trust: String,
    deployment: String,
}

impl Hosted {
    fn new(fixture: &Fixture, host: &Host) -> Self {
        use ring::signature::KeyPair as _;
        let sql = RusqliteDoSql::with_store_schema();
        let public_bindings: Vec<Value> = [("owner", 1u8), ("worker", 2u8)]
            .into_iter()
            .map(|(name, seed)| {
                let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
                    .expect("synthetic key");
                let public_key_hex: String = key
                    .public_key()
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                json!({"actor":{"principal":name,"algorithm":"ed25519-custodian","key_id":format!("credential:norm/{name}#local")},"public_key_hex":public_key_hex})
            })
            .collect();
        let _ = fixture;
        let image = format!("sha256:{}", "c".repeat(64));
        let deployment = json!({
            "planning": host.planning.to_string(),
            "runtime": json!(host.runtime).to_string(),
            "deployed_image": image,
            "image_binding": json!({"protocol":"whipplescript.exec.runtime-image/v1","image_id":image,"runtime":host.runtime}).to_string(),
            "time_basis": "hosted-demo",
        })
        .to_string();
        whipplescript_host_do::do_branches::compose_vcs_shared(&sql)
            .expect("hosted workspace")
            .init("t0")
            .expect("hosted mainline");
        DoSqliteStore::new(sql.clone())
            .register_script_capability(ScriptCapabilityRegistration {
                name: &host.installed.name,
                argv_json: &host.installed.argv_json,
                sha256: &host.installed.sha256,
                env_json: &host.installed.env_json,
                hermetic: false,
                body: &host.installed.body,
            })
            .expect("hosted observer");
        Self {
            sql,
            trust: json!({"bindings":[],"public_bindings":public_bindings,"creation_grants":[]})
                .to_string(),
            deployment,
        }
    }

    fn write(&self, branch: &str, path: &str, body: &str, cut: &str, at: &str) {
        let written = whipplescript_host_do::do_branches::compose_vcs_shared(&self.sql)
            .expect("hosted workspace")
            .write(branch, path, Some(body), cut, at)
            .expect("hosted write");
        assert!(
            matches!(
                written,
                whipplescript_store::vcs::VcsWriteOutcome::Written { .. }
            ),
            "{written:?}"
        );
    }

    /// Bring the object's ledger up to the native one, through the hosted
    /// command door, whose first import leases the mainline to its gate.
    fn sync(&self, fixture: &Fixture) {
        let (checkpoint, events) = with_view(fixture, |ledger, _, _| {
            (
                ledger
                    .norm_checkpoint()
                    .expect("checkpoint")
                    .expect("pinned"),
                ledger.export_events().expect("history"),
            )
        });
        let mut store = DoSqliteStore::new(self.sql.clone());
        store
            .pin_norm_checkpoint(&checkpoint)
            .expect("independent host pin");
        let sql = self.sql.clone();
        let mut lease = || {
            whipplescript_store::branches::lease_gated_mainline(
                &mut whipplescript_host_do::do_branches::DoBranches::new(sql.clone())?,
                "hosted-import",
            )
        };
        execute_hosted_norm_command_with_artifacts(
            &mut store,
            &self.trust,
            &json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"import","events":events}}).to_string(),
            None,
            Some(&mut lease),
        )
        .expect("the object admits the native history");
    }

    fn promote(&self, promotion: &str, tokens: &[&str]) -> Value {
        let answer = whipplescript_host_do::norm_commands::execute_installed_hosted_norm_promotion(
            &self.sql,
            &self.trust,
            &json!({"protocol":"whipplescript.norm.promotion/v1","command":{"stream":"work","promotion":promotion,"tokens":tokens}}).to_string(),
            &self.deployment,
        )
        .expect("the hosted door answers");
        serde_json::from_str::<Value>(&answer).expect("promotion JSON")["result"].clone()
    }

    fn impact(&self, before: &str, after: &str, requirement: &str) -> Vec<String> {
        let sql = self.sql.clone();
        let answer = whipplescript_host_do::norm_commands::execute_installed_hosted_norm_impact(
            &DoSqliteStore::new(self.sql.clone()),
            &self.trust,
            &json!({"protocol":"whipplescript.norm.impact/v1","command":{"before_cut":before,"after_cut":after}}).to_string(),
            &|cut| {
                whipplescript_host_do::do_branches::compose_vcs_shared(&sql)?
                    .capture_norm_artifact(cut, ArtifactLimits::default())
            },
            &self.deployment,
        )
        .expect("the hosted query answers");
        let answer: Value = serde_json::from_str(&answer).expect("impact JSON");
        work_kinds(&answer["result"], requirement)
    }

    fn read(&self, branch: &str, path: &str) -> Option<String> {
        whipplescript_host_do::do_branches::compose_vcs_shared(&self.sql)
            .expect("hosted workspace")
            .read(branch, path)
            .expect("hosted read")
    }

    fn snapshot_at(&self, frontier: &Value) -> Value {
        let answer = execute_hosted_norm_command_with_artifacts(
            &mut DoSqliteStore::new(self.sql.clone()),
            &self.trust,
            &json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"snapshot_at","frontier":frontier}}).to_string(),
            None,
            None,
        )
        .expect("hosted historical snapshot");
        serde_json::from_str::<Value>(&answer).expect("snapshot JSON")["result"]["snapshot"].clone()
    }
}

/// The work a planned requirement's support needs, as either host answers.
fn work_kinds(planned: &Value, requirement: &str) -> Vec<String> {
    planned["plan"]["requirements"][requirement]
        .as_array()
        .map(|impacts| {
            impacts
                .iter()
                .map(|impact| {
                    impact["work"]["kind"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What `norm impact` says the requirement's support needs at `after`.
fn impact(
    fixture: &Fixture,
    host: &Host,
    before: &str,
    after: &str,
    requirement: &str,
) -> Vec<String> {
    let output = whip(
        fixture,
        &["--json", "norm", "impact", before, after],
        host.configured(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let planned: Value = serde_json::from_slice(&output.stdout).expect("impact JSON");
    let planned = if planned.get("plan").is_some() {
        planned
    } else {
        planned["result"].clone()
    };
    work_kinds(&planned, requirement)
}

fn promote(fixture: &Fixture, host: &Host, tokens: &[&str]) -> Output {
    let mut args = vec!["stream", "promote", "work"];
    for token in tokens {
        args.extend(["--token", token]);
    }
    whip(fixture, &args, host.configured())
}

fn refused(output: &Output) -> Value {
    assert!(
        !output.status.success(),
        "the mainline moved: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).expect("refusal JSON")
}

fn read(fixture: &Fixture, branch: &str, path: &str) -> Option<String> {
    NativeWorkspaceVcs::open(
        fixture.root.join("branches.sqlite"),
        fixture.root.join("content.sqlite"),
    )
    .expect("workspace")
    .read(branch, path)
    .expect("read")
}

fn line_write(fixture: &Fixture, body: &str, cut: &str, at: &str) {
    NativeWorkspaceVcs::open(
        fixture.root.join("branches.sqlite"),
        fixture.root.join("content.sqlite"),
    )
    .expect("workspace")
    .write("line-work", "src/parser.py", Some(body), cut, at)
    .expect("line write");
}

fn snapshot(fixture: &Fixture, frontier: Option<&str>) -> Value {
    let mut args = vec!["snapshot"];
    if let Some(frontier) = frontier {
        args.extend(["--frontier", frontier]);
    }
    fixture.run(&args)
}

/// NP-19, NP-20 and NP-22 over `examples/authorization-demo`, natively.
#[test]
fn the_authorization_demo_repairs_a_violated_requirement_under_a_current_token() {
    let fixture = Fixture::new();
    let charter: NormCharter =
        serde_json::from_str(&demo("charter.json")).expect("C0 is a charter");
    let host = Host::install(&fixture, &charter);
    let hosted = Hosted::new(&fixture, &host);

    // A0: the demo's workspace on Main, and W's stream line `work` off it, on
    // both hosts. The ledger's bootstrap then leases each mainline to its gate.
    let mut vcs = NativeWorkspaceVcs::open(
        fixture.root.join("branches.sqlite"),
        fixture.root.join("content.sqlite"),
    )
    .expect("workspace");
    vcs.init("t0").expect("init");
    for (index, path) in ["src/parser.py", "src/auth.py", "checks/q0.json"]
        .into_iter()
        .enumerate()
    {
        let cut = if index == 2 {
            "a0".to_owned()
        } else {
            format!("a0-{index}")
        };
        vcs.write(MAINLINE_BRANCH_ID, path, Some(&demo(path)), &cut, "t1")
            .expect("A0");
        hosted.write(MAINLINE_BRANCH_ID, path, &demo(path), &cut, "t1");
    }
    vcs.create_branch("line-work", None, MAINLINE_BRANCH_ID, "t2")
        .expect("work line");
    WorkstreamStore::open(fixture.root.join("workstreams.sqlite"))
        .expect("streams")
        .create_stream("work", None, "line-work", "t2", None)
        .expect("work stream");
    drop(vcs);
    whipplescript_host_do::do_branches::compose_vcs_shared(&hosted.sql)
        .expect("hosted workspace")
        .create_branch("line-work", None, MAINLINE_BRANCH_ID, "t2")
        .expect("hosted work line");
    whipplescript_host_do::do_workstreams::DoWorkstreams::new(hosted.sql.clone())
        .expect("hosted streams")
        .create_stream("work", None, "line-work", "t2", None)
        .expect("hosted work stream");

    // C0, bootstrapped by W on O's behalf.
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
    // R0, owned and accepted by O.
    fixture.write(
        "r0.json",
        &json!({
            "name": REQUIREMENT,
            "proposition": "for role in {owner, worker} and grant in {allow, deny}, authorized iff role == owner or grant == allow",
            "domain": "authorization",
            "subject": "src/auth.py",
            "applicability": "the authorization domain",
            "owner": "owner",
            "support_contract": host.support,
        }),
    );
    let requirement = fixture.run(&[
        "create",
        "requirement@1",
        "--as",
        "owner",
        "--fields",
        "r0.json",
    ])["result"]["event_id"]
        .as_str()
        .expect("R0")
        .to_owned();
    fixture.run(&["transition", &requirement, "accepted", "--as", "owner"]);

    // D0, whose acceptance only O's authority can give (NP-02).
    fixture.write(
        "d0.json",
        &json!({
            "title": "Authorize by role or grant",
            "question": "who may act on custody",
            "course": "owners always, workers when a grant allows",
            "rationale": "least authority",
            "alternatives": ["grants only"],
            "scope": "src/auth.py",
            "consequences": "the parser interprets grants",
            "subjects": ["src/auth.py"],
        }),
    );
    let decision = fixture.run(&[
        "create",
        "decision@1",
        "--as",
        "worker",
        "--fields",
        "d0.json",
    ])["result"]["event_id"]
        .as_str()
        .expect("D0")
        .to_owned();
    fixture.refuse(&["transition", &decision, "accepted", "--as", "worker"]);
    fixture.run(&["transition", &decision, "accepted", "--as", "owner"]);

    // NP-22: D0 folded into R0 by O's attestation, and R0 implemented at A0
    // with adequate tested support. Editing D0's intent establishes nothing;
    // the worker cannot attest incorporation.
    let (d0, r0, basis) = with_view(&fixture, |_, view, _| {
        (
            view.effective_records[&decision].content_head.clone(),
            view.effective_records[&requirement].content_head.clone(),
            view.relation_family("incorporation")
                .expect("incorporation family")
                .basis,
        )
    });
    fixture.write("fold.json", &json!({"source": d0, "target": r0}));
    let references = format!("{d0},{r0}");
    let fold = |actor: &str| {
        vec![
            "create",
            "incorporates@1",
            "--as",
            actor,
            "--fields",
            "fold.json",
            "--family-basis",
            basis.as_str(),
            "--references",
            references.as_str(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    };
    let worker_fold = fold("worker");
    fixture.refuse(&worker_fold.iter().map(String::as_str).collect::<Vec<_>>());
    let owner_fold = fold("owner");
    let folding = fixture.run(&owner_fold.iter().map(String::as_str).collect::<Vec<_>>())["result"]
        ["event_id"]
        .as_str()
        .expect("folding")
        .to_owned();
    observe(&fixture, &host, &hosted, &requirement, "a0", "a0", &[]);
    assert_eq!(
        impact(&fixture, &host, "a0", "a0", &requirement),
        ["supported"]
    );
    let historical = with_view(&fixture, |_, view, _| view.frontier.clone());
    fixture.write("historical.json", &json!(historical));
    let folded = snapshot(&fixture, Some("historical.json"));
    hosted.sync(&fixture);
    assert_eq!(hosted.impact("a0", "a0", &requirement), ["supported"]);

    // W's exclusive reservation of `src/**`, granted by O: T1.
    fixture.write(
        "claim.json",
        &json!({"purpose": "repair the parser", "selectors": ["src/**"], "mode": "exclusive"}),
    );
    let claim = fixture.run(&[
        "create",
        "reservation@1",
        "--as",
        "worker",
        "--fields",
        "claim.json",
    ])["result"]["event_id"]
        .as_str()
        .expect("claim")
        .to_owned();
    fixture.refuse(&["transition", &claim, "granted", "--as", "worker"]);
    let t1 = fixture.run(&["transition", &claim, "granted", "--as", "owner"])["result"]["event_id"]
        .as_str()
        .expect("T1")
        .to_owned();

    // A1: the negative mutation on `work`. The subject is byte-identical,
    // but support at A0 does not carry to it (NP-07, current conformance
    // stale); Q0 finds the located worker-deny counterexample (contradicted),
    // and promotion under T1 is refused naming R0 with Main unmoved.
    line_write(&fixture, MUTATED, "a1", "t3");
    hosted.write("line-work", "src/parser.py", MUTATED, "a1", "t3");
    assert_eq!(
        read(&fixture, "line-work", "src/auth.py"),
        Some(demo("src/auth.py"))
    );
    assert_eq!(impact(&fixture, &host, "a0", "a1", &requirement), ["check"]);
    hosted.sync(&fixture);
    assert_eq!(hosted.impact("a0", "a1", &requirement), ["check"]);
    observe(
        &fixture,
        &host,
        &hosted,
        &requirement,
        "a1",
        "a1",
        &["worker-deny"],
    );
    assert_eq!(
        impact(&fixture, &host, "a0", "a1", &requirement),
        ["repair"]
    );
    hosted.sync(&fixture);
    assert_eq!(hosted.impact("a0", "a1", &requirement), ["repair"]);
    let violated = refused(&promote(&fixture, &host, &[&t1]));
    assert_eq!(
        violated["detail"]["requirements"][&requirement],
        json!(["repair"])
    );
    assert_eq!(
        read(&fixture, MAINLINE_BRANCH_ID, "src/parser.py"),
        Some(demo("src/parser.py"))
    );
    let hosted_violated = hosted.promote("violated", &[&t1]);
    assert_eq!(
        hosted_violated["detail"]["requirements"][&requirement],
        json!(["repair"])
    );
    assert_eq!(hosted_violated["reason"], violated["reason"]);
    assert_eq!(
        hosted.read(MAINLINE_BRANCH_ID, "src/parser.py"),
        Some(demo("src/parser.py"))
    );

    // NP-22: the folding and the implementation support at A0 are history;
    // the view at their frontier is exactly what it was, and the current
    // view still carries them after conformance was contradicted.
    // (A historical read carries today's verification anchor beside it.)
    assert_eq!(
        snapshot(&fixture, Some("historical.json"))["result"]["snapshot"],
        folded["result"]["snapshot"]
    );
    let current = snapshot(&fixture, None);
    assert!(current.to_string().contains(&folding));
    // Local names follow each host's admission order; the signed history
    // and everything derived from it are what must agree.
    let without_aliases = |mut snapshot: Value| {
        for named in snapshot["records"].as_array_mut().expect("records") {
            named.as_object_mut().expect("named record").remove("alias");
        }
        snapshot
    };
    assert_eq!(
        without_aliases(hosted.snapshot_at(&json!(historical))),
        without_aliases(folded["result"]["snapshot"].clone()),
        "the hosted object reads the same history at the folding's frontier"
    );

    // A2: W repairs the parser on `work`. Until fresh support exists for the
    // repaired result, promotion is refused (NP-19's premise).
    line_write(&fixture, REPAIRED, "a2", "t4");
    hosted.write("line-work", "src/parser.py", REPAIRED, "a2", "t4");
    assert_eq!(impact(&fixture, &host, "a0", "a2", &requirement), ["check"]);
    assert_eq!(
        refused(&promote(&fixture, &host, &[&t1]))["detail"]["requirements"][&requirement],
        json!(["check"])
    );
    observe(&fixture, &host, &hosted, &requirement, "a2", "a2", &[]);
    assert_eq!(
        impact(&fixture, &host, "a0", "a2", &requirement),
        ["supported"]
    );

    // A change to the reserved region is admitted only under the current
    // token: none presented refuses, naming the reservation.
    let unfenced = refused(&promote(&fixture, &host, &[]));
    assert_eq!(
        unfenced["detail"]["reservations"][&claim],
        "src/parser.py is reserved, and its current token was not presented"
    );

    // NP-20: T1 expires and T2 is granted on a fresh claim; the old holder's
    // T1 is stale and refuses.
    fixture.run(&["transition", &claim, "expired", "--as", "owner"]);
    let renewed = fixture.run(&[
        "create",
        "reservation@1",
        "--as",
        "worker",
        "--fields",
        "claim.json",
    ])["result"]["event_id"]
        .as_str()
        .expect("renewed claim")
        .to_owned();
    let t2 = fixture.run(&["transition", &renewed, "granted", "--as", "owner"])["result"]
        ["event_id"]
        .as_str()
        .expect("T2")
        .to_owned();
    let stale = refused(&promote(&fixture, &host, &[&t1]));
    assert!(
        stale["detail"]["reservations"].get(&renewed).is_some(),
        "{stale}"
    );
    assert_eq!(
        read(&fixture, MAINLINE_BRANCH_ID, "src/parser.py"),
        Some(demo("src/parser.py"))
    );

    // The hosted object answers each of these the same way.
    hosted.sync(&fixture);
    assert_eq!(hosted.impact("a0", "a2", &requirement), ["supported"]);
    // (By now the fence is the renewed grant: the first one has expired.)
    assert_eq!(
        hosted.promote("unfenced", &[])["detail"]["reservations"][&renewed],
        unfenced["detail"]["reservations"][&claim]
    );
    assert_eq!(
        hosted.promote("stale", &[&t1])["detail"]["reservations"],
        stale["detail"]["reservations"]
    );
    assert_eq!(
        hosted.read(MAINLINE_BRANCH_ID, "src/parser.py"),
        Some(demo("src/parser.py"))
    );

    // NP-19: the repair, freshly supported, admitted under the current T2.
    let admitted = promote(&fixture, &host, &[&t2]);
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stdout)
    );
    assert_eq!(
        read(&fixture, MAINLINE_BRANCH_ID, "src/parser.py").as_deref(),
        Some(REPAIRED)
    );
    let hosted_admitted = hosted.promote("repaired", &[&t2]);
    assert_eq!(hosted_admitted["promoted"], "work", "{hosted_admitted}");
    assert_eq!(
        hosted.read(MAINLINE_BRANCH_ID, "src/parser.py").as_deref(),
        Some(REPAIRED)
    );

    // The failure and its fixing cut stay inspectable: both observations
    // and the passing one are in the ledger, the counterexample located at
    // worker-deny, and `work` holds the fixing cut after the failing one.
    let observations: Vec<String> = snapshot(&fixture, None)["result"]["snapshot"]["records"]
        .as_array()
        .map(|records| {
            records
                .iter()
                .map(|entry| &entry["record"])
                .filter(|record| record["vocabulary"]["name"] == "local-observation")
                .map(|record| {
                    record["fields"]["observation_json"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(observations.len(), 3, "{observations:?}");
    assert!(observations
        .iter()
        .any(|observation| observation.contains("worker-deny")
            && observation.contains("\"actual\":true")));
    let chain = NativeWorkspaceVcs::open(
        fixture.root.join("branches.sqlite"),
        fixture.root.join("content.sqlite"),
    )
    .expect("workspace")
    .cut_chain("a2", "a0")
    .expect("chain")
    .expect("a2 descends from a0");
    let cuts: Vec<&str> = chain.iter().map(|cut| cut.cut_id.as_str()).collect();
    assert_eq!(
        cuts,
        ["a0", "a1", "a2"],
        "the fixing cut follows the failing one"
    );
}
