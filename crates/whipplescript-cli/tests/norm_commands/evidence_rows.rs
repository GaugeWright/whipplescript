//! The norm plane's evidence rows over `examples/authorization-demo`, on both
//! hosts (norm-plane admission fixtures, N1): NP-03's tested support that is
//! never labelled proof, NP-04's harness failures and the one issue an
//! investigation files, NP-05's swallowed failure, NP-08's read outside the
//! declared domain, NP-09's invalidation without a subject change, and NP-11's
//! concurrent pass and fail folded in either order.
//!
//! Each row runs natively (`WorkItemStore`, `SqliteStore`,
//! `NativeWorkspaceVcs`, the `whip` CLI) and on the hosted workspace object
//! (`DoSqliteStore` over `RusqliteDoSql`, `DoBranches`, and the hosted
//! command doors), and asserts the same answer from both.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use whipplescript_core::norm_evidence::RequiredCase;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_custody::client::UnixSocketTransport;
use whipplescript_host_do::do_store::test_support::RusqliteDoSql;
use whipplescript_host_do::do_store::DoSqliteStore;
use whipplescript_host_do::norm_commands::{
    execute_hosted_norm_command_with_artifacts, execute_hosted_norm_publication,
};
use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
use whipplescript_kernel::norm_execution::{
    fixtures as execution, NormRunSelection, PreparedNormExecution, PythonCallSupport,
};
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_kernel::norm_runner::{
    PythonCallMethod, PythonCase, PythonEngine, PythonRuntime,
};
use whipplescript_kernel::sansio::HttpResponse;
use whipplescript_store::branches::MAINLINE_BRANCH_ID;
use whipplescript_store::items::{TrackerEvent, WorkItemStore};
use whipplescript_store::norm::{NormCharter, NormCheckpoint, NormView};
use whipplescript_store::norm_artifact::ArtifactLimits;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::workstreams::{WorkstreamStore, Workstreams};
use whipplescript_store::{RuntimeStore, ScriptCapabilityRegistration, SqliteStore};

const MUTATED: &str = "def grant_allows(grant):\n    return grant in (\"allow\", \"deny\")\n";
const REPAIRED: &str =
    "def grant_allows(grant):\n    # Only an explicit allowing grant allows.\n    return grant == \"allow\"\n";
const CASES: [&str; 4] = ["owner-allow", "owner-deny", "worker-allow", "worker-deny"];

/// A file of the checked-in demo workspace.
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

/// The protected runtime the hosts install first.
fn runtime() -> PythonRuntime {
    let mut method = execution::method();
    method.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/reactor.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    method.runtime.executable = "/usr/local/bin/whip".into();
    method.runtime
}

/// Q0, the demo's four-case check, over `runtime`. With `keywords` its cases
/// pass their inputs by name rather than by position: the same check, as
/// another method definition.
fn q0(runtime: &PythonRuntime, keywords: bool) -> (PythonCallMethod, Vec<RequiredCase>) {
    let q0: Value = serde_json::from_str(&demo("checks/q0.json")).expect("Q0");
    let cases = q0["cases"].as_array().expect("Q0 cases");
    let method = PythonCallMethod {
        runtime: runtime.clone(),
        module: q0["module"].as_str().expect("module").into(),
        function: q0["function"].as_str().expect("function").into(),
        cases: cases
            .iter()
            .map(|case| {
                let (args, kwargs) = if keywords {
                    (
                        Vec::new(),
                        [
                            ("role".to_owned(), case["role"].clone()),
                            ("grant".to_owned(), case["grant"].clone()),
                        ]
                        .into(),
                    )
                } else {
                    (
                        vec![case["role"].clone(), case["grant"].clone()],
                        BTreeMap::new(),
                    )
                };
                PythonCase {
                    id: case["id"].as_str().expect("id").into(),
                    args,
                    kwargs,
                }
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

/// R0's support contract: Q0 as a method definition.
fn support(runtime: &PythonRuntime, keywords: bool) -> String {
    let (method, cases) = q0(runtime, keywords);
    json!(PythonCallSupport::V1 { method, cases }).to_string()
}

/// R0's declaration with `support` as its contract.
fn requirement_fields(support: &str) -> Value {
    json!({
        "name": "custody-authorization",
        "proposition": "for role in {owner, worker} and grant in {allow, deny}, authorized iff role == owner or grant == allow",
        "domain": "authorization",
        "subject": "src/auth.py",
        "applicability": "the authorization domain",
        "owner": "owner",
        "support_contract": support,
    })
}

/// The demo's host: the protected runtime, the installed observer, and how
/// to read every vocabulary of the charter.
struct Host {
    planning: Value,
    path: PathBuf,
    installed: whipplescript_store::ScriptCapabilityRecord,
    required: Vec<RequiredCase>,
    runtime: PythonRuntime,
}

impl Host {
    /// Install `runtime` natively: the observer registered in the runtime
    /// store and the host configuration naming the installed image.
    fn install(fixture: &Fixture, charter: &NormCharter, runtime: PythonRuntime) -> Self {
        let (method, required) = q0(&runtime, false);
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
        fixture.write("host.json", &json!({"protocol":"whipplescript.exec.native-norm-host/v1","endpoint":"unix:///no-query-executor","installed":{"protocol":"whipplescript.exec.native-runtime-image/v1","daemon_id":"fixture-daemon","base_image":format!("sha256:{}", "b".repeat(64)),"image_id":format!("sha256:{}", "c".repeat(64)),"runtime":runtime}}));
        let roles: Vec<Value> = charter
            .vocabularies
            .iter()
            .map(|entry| {
                let interpretation = match entry.definition.name.as_str() {
                    "local-observation" => "published_execution",
                    "reservation" => "reservation",
                    "quarantine" => "quarantine",
                    "sampling-policy" => "sampling_policy",
                    "exception" => "exception",
                    _ => "context",
                };
                json!({
                    "vocabulary": Vocabulary::new(entry.definition.clone()).expect("charter").reference(),
                    "interpretation": interpretation,
                })
            })
            .collect();
        Self {
            planning: json!({"capability": "observer", "roles": roles}),
            path: fixture.root.join("host.json"),
            installed,
            required,
            runtime,
        }
    }

    fn configured(&self) -> Option<(&Value, &Path)> {
        Some((&self.planning, &self.path))
    }
}

/// `whip` against the fixture's stores, with `items` as the ledger.
fn whip_in(
    fixture: &Fixture,
    items: &Path,
    args: &[&str],
    host: Option<(&Value, &Path)>,
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
        .env("WHIPPLESCRIPT_ITEMS_STORE", items)
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

/// The ledger at `items` as the fixture's principals signed it, read in
/// process.
fn with_view<T>(
    fixture: &Fixture,
    items: &Path,
    read: impl FnOnce(&mut WorkItemStore, &NormView, &dyn whipplescript_store::norm::NormVerifier) -> T,
) -> T {
    with_verifier(fixture, |verifier| {
        let mut ledger = WorkItemStore::open(items).expect("ledger");
        let view = ledger.norm_view(verifier).expect("verified view");
        read(&mut ledger, &view, verifier)
    })
}

/// The fixture's principals, as a host verifies their signatures.
fn with_verifier<T>(
    fixture: &Fixture,
    read: impl FnOnce(&dyn whipplescript_store::norm::NormVerifier) -> T,
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
    read(&verifier)
}

/// A hosted workspace object: its own branches, content and runtime journal,
/// a ledger imported through the hosted command door under deployment trust,
/// and the hosted doors answering.
struct Hosted {
    sql: RusqliteDoSql,
    trust: String,
    deployment: String,
}

impl Hosted {
    /// A fresh object holding the demo's A0 on its mainline and W's line
    /// `work`, with `host`'s observer registered.
    fn new(host: &Host) -> Self {
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
        let hosted = Self {
            sql,
            trust: json!({"bindings":[],"public_bindings":public_bindings,"creation_grants":[]})
                .to_string(),
            deployment: String::new(),
        };
        let mut hosted = hosted;
        hosted.redeploy(host);
        let vcs = || {
            whipplescript_host_do::do_branches::compose_vcs_shared(&hosted.sql)
                .expect("hosted workspace")
        };
        vcs().init("t0").expect("hosted mainline");
        DoSqliteStore::new(hosted.sql.clone())
            .register_script_capability(ScriptCapabilityRegistration {
                name: &host.installed.name,
                argv_json: &host.installed.argv_json,
                sha256: &host.installed.sha256,
                env_json: &host.installed.env_json,
                hermetic: false,
                body: &host.installed.body,
            })
            .expect("hosted observer");
        for (path, cut) in A0 {
            hosted.write(MAINLINE_BRANCH_ID, path, &demo(path), cut, "t1");
        }
        vcs()
            .create_branch("line-work", None, MAINLINE_BRANCH_ID, "t2")
            .expect("hosted work line");
        whipplescript_host_do::do_workstreams::DoWorkstreams::new(hosted.sql.clone())
            .expect("hosted streams")
            .create_stream("work", None, "line-work", "t2", None)
            .expect("hosted work stream");
        hosted
    }

    /// Deploy `host`'s runtime and planning to the object.
    fn redeploy(&mut self, host: &Host) {
        let image = format!("sha256:{}", "c".repeat(64));
        self.deployment = json!({
            "planning": host.planning.to_string(),
            "runtime": json!(host.runtime).to_string(),
            "deployed_image": image,
            "image_binding": json!({"protocol":"whipplescript.exec.runtime-image/v1","image_id":image,"runtime":host.runtime}).to_string(),
            "time_basis": "hosted-evidence",
            "now": format!(
                "unix:{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_secs()
            ),
        })
        .to_string();
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

    /// Import `events` through the hosted command door, pinning `checkpoint`
    /// first if the object holds none. The first import leases the mainline
    /// to its gate.
    fn import(&self, checkpoint: &NormCheckpoint, events: &[TrackerEvent]) -> Value {
        let mut store = DoSqliteStore::new(self.sql.clone());
        if store
            .norm_checkpoint()
            .expect("hosted checkpoint")
            .is_none()
        {
            store
                .pin_norm_checkpoint(checkpoint)
                .expect("independent host pin");
        }
        let sql = self.sql.clone();
        let mut lease = |declared: &[String]| {
            whipplescript_store::branches::lease_gated_refs(
                &mut whipplescript_host_do::do_branches::DoBranches::new(sql.clone())?,
                declared,
                "hosted-import",
            )
        };
        let answer = execute_hosted_norm_command_with_artifacts(
            &mut store,
            &self.trust,
            &json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"import","events":events}}).to_string(),
            None,
            Some(&mut lease),
            None,
            None,
        )
        .expect("the object admits the history");
        serde_json::from_str::<Value>(&answer).expect("import JSON")["result"].clone()
    }

    /// Bring the object's ledger up to the native one.
    fn sync(&self, fixture: &Fixture) -> Value {
        let (checkpoint, events) = with_view(
            fixture,
            &fixture.root.join("items.sqlite"),
            |ledger, _, _| {
                (
                    ledger
                        .norm_checkpoint()
                        .expect("checkpoint")
                        .expect("pinned"),
                    ledger.export_events().expect("history"),
                )
            },
        );
        self.import(&checkpoint, &events)
    }

    /// One norm command through the hosted door.
    fn command(&self, command: Value) -> Result<Value, String> {
        execute_hosted_norm_command_with_artifacts(
            &mut DoSqliteStore::new(self.sql.clone()),
            &self.trust,
            &json!({"protocol":"whipplescript.norm.commands/v1","command":command}).to_string(),
            None,
            None,
            None,
            None,
        )
        .map(|answer| {
            serde_json::from_str::<Value>(&answer).expect("command JSON")["result"].clone()
        })
    }

    /// The hosted publication door's preparation of a settled run: what it
    /// would ask the owner to sign, or its refusal.
    fn prepare_publication(&self, run: &str) -> Result<Value, String> {
        let sql = self.sql.clone();
        execute_hosted_norm_publication(
            &mut DoSqliteStore::new(self.sql.clone()),
            &self.trust,
            &json!({"protocol":"whipplescript.norm.publication/v1","command":{
                "kind":"prepare","instance":format!("instance-{run}"),"run":format!("run-{run}"),
                "vocabulary":"local-observation@1",
                "actor":{"principal":"owner","algorithm":"ed25519-custodian","key_id":"credential:norm/owner#local"},
                "created_at":"2026-09-28T00:00:00Z"
            }})
            .to_string(),
            &|cut| {
                whipplescript_host_do::do_branches::compose_vcs_shared(&sql)?
                    .capture_norm_artifact(cut, ArtifactLimits::default())
            },
        )
        .map(|answer| serde_json::from_str::<Value>(&answer).expect("publication JSON"))
    }

    fn promote(&self, promotion: &str) -> Value {
        let answer = whipplescript_host_do::norm_commands::execute_installed_hosted_norm_promotion(
            &self.sql,
            &self.trust,
            &json!({"protocol":"whipplescript.norm.promotion/v1","command":{"stream":"work","promotion":promotion,"tokens":[]}}).to_string(),
            &self.deployment,
        )
        .expect("the hosted door answers");
        serde_json::from_str::<Value>(&answer).expect("promotion JSON")["result"].clone()
    }

    fn planned(&self, before: &str, after: &str) -> Value {
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
        serde_json::from_str::<Value>(&answer).expect("impact JSON")["result"].clone()
    }

    fn read(&self, branch: &str, path: &str) -> Option<String> {
        whipplescript_host_do::do_branches::compose_vcs_shared(&self.sql)
            .expect("hosted workspace")
            .read(branch, path)
            .expect("hosted read")
    }
}

/// The demo's A0: each file and the cut that writes it.
const A0: [(&str, &str); 3] = [
    ("src/parser.py", "a0-0"),
    ("src/auth.py", "a0-1"),
    ("checks/q0.json", "a0"),
];

/// What a fixture run's executor receipt reports.
struct Run<'a> {
    /// The cases the report observes; every required case when `None`.
    only: Option<&'a [&'a str]>,
    /// The cases whose returned value is the opposite of what R0 expects.
    wrong: &'a [&'a str],
    /// Whether the process exits nonzero.
    failed: bool,
}

/// Every case observed, as R0 expects, and a zero exit.
const PASSING: Run<'static> = Run {
    only: None,
    wrong: &[],
    failed: false,
};

/// The demo's workspace and ledger on both hosts: A0 on each mainline, W's
/// line `work` off it, C0 bootstrapped (with an issue vocabulary to file
/// investigations under), and R0 accepted with Q0 as its support contract.
struct World {
    fixture: Fixture,
    charter: NormCharter,
    host: Host,
    hosted: Hosted,
    requirement: String,
}

impl World {
    fn new() -> Self {
        let fixture = Fixture::new();
        let mut charter: NormCharter =
            serde_json::from_str(&demo("charter.json")).expect("C0 is a charter");
        charter.vocabularies.push(
            NormCharter::bundled()
                .expect("bundled charter")
                .vocabularies
                .into_iter()
                .find(|entry| entry.definition.name == "issue")
                .expect("the bundled issue vocabulary"),
        );
        let host = Host::install(&fixture, &charter, runtime());
        let hosted = Hosted::new(&host);
        let mut vcs = NativeWorkspaceVcs::open(
            fixture.root.join("branches.sqlite"),
            fixture.root.join("content.sqlite"),
        )
        .expect("workspace");
        vcs.init("t0").expect("init");
        for (path, cut) in A0 {
            vcs.write(MAINLINE_BRANCH_ID, path, Some(&demo(path)), cut, "t1")
                .expect("A0");
        }
        vcs.create_branch("line-work", None, MAINLINE_BRANCH_ID, "t2")
            .expect("work line");
        WorkstreamStore::open(fixture.root.join("workstreams.sqlite"))
            .expect("streams")
            .create_stream("work", None, "line-work", "t2", None)
            .expect("work stream");
        drop(vcs);
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
        fixture.write(
            "r0.json",
            &requirement_fields(&support(&host.runtime, false)),
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
        hosted.sync(&fixture);
        Self {
            fixture,
            charter,
            host,
            hosted,
            requirement,
        }
    }

    fn items(&self) -> PathBuf {
        self.fixture.root.join("items.sqlite")
    }

    /// Write `path` on W's line on both hosts.
    fn line(&self, path: &str, body: &str, cut: &str, at: &str) {
        NativeWorkspaceVcs::open(
            self.fixture.root.join("branches.sqlite"),
            self.fixture.root.join("content.sqlite"),
        )
        .expect("workspace")
        .write("line-work", path, Some(body), cut, at)
        .expect("line write");
        self.hosted.write("line-work", path, body, cut, at);
    }

    fn read(&self, branch: &str, path: &str) -> Option<String> {
        NativeWorkspaceVcs::open(
            self.fixture.root.join("branches.sqlite"),
            self.fixture.root.join("content.sqlite"),
        )
        .expect("workspace")
        .read(branch, path)
        .expect("read")
    }

    /// Prepare Q0 on a stored cut through the verified execution path.
    fn prepare(&self, cut: &str, run: &str) -> PreparedNormExecution {
        with_view(&self.fixture, &self.items(), |ledger, view, verifier| {
            let history = CapturedNormHistory::capture(
                view,
                &ledger.export_events().expect("history"),
                verifier,
                NormHistoryLimits::default(),
            )
            .expect("history");
            let artifact = NativeWorkspaceVcs::open(
                self.fixture.root.join("branches.sqlite"),
                self.fixture.root.join("content.sqlite"),
            )
            .expect("workspace")
            .capture_norm_artifact(cut, ArtifactLimits::default())
            .expect("candidate");
            let effect = format!("observe-{run}");
            PreparedNormExecution::prepare(
                &history,
                verifier,
                &artifact,
                &self.host.installed,
                NormRunSelection {
                    effect_id: &effect,
                    ..execution::selection(&view.ledger, &self.requirement)
                },
            )
            .expect("prepared execution")
        })
    }

    /// The executor receipt a run of `prepared` reports, before `tamper`.
    fn receipt(&self, prepared: &PreparedNormExecution, run: &Run<'_>) -> HttpResponse {
        let cases: Vec<(&str, &str, Value)> = self
            .host
            .required
            .iter()
            .filter(|case| run.only.is_none_or(|only| only.contains(&case.id.as_str())))
            .map(|case| {
                let expected = case.expected.as_bool().expect("boolean case");
                let actual = expected != run.wrong.contains(&case.id.as_str());
                (case.id.as_str(), case.assertion.as_str(), json!(actual))
            })
            .collect();
        execution::receipt_cases(prepared, &cases, run.failed)
    }

    /// Settle `prepared`'s run in the native journal and in each hosted
    /// object's, so every host's own recovery reconstructs it.
    fn journal(
        &self,
        prepared: &PreparedNormExecution,
        receipt: &HttpResponse,
        failed: bool,
        run: &str,
        hosted: &[&Hosted],
    ) {
        drop(execution::journal_execution_as(
            SqliteStore::open(self.fixture.root.join("runtime.sqlite")).expect("runtime"),
            prepared,
            receipt,
            failed,
            &format!("instance-{run}"),
            &format!("run-{run}"),
        ));
        for hosted in hosted {
            drop(execution::journal_execution_as(
                DoSqliteStore::new(hosted.sql.clone()),
                prepared,
                receipt,
                failed,
                &format!("instance-{run}"),
                &format!("run-{run}"),
            ));
        }
    }

    /// Publish a settled run's observation onto the ledger at `items`.
    fn publish(&self, items: &Path, run: &str, at: Option<&str>) -> Result<String, String> {
        let (instance, run_id) = (format!("instance-{run}"), format!("run-{run}"));
        let mut args = vec![
            "--json",
            "norm",
            "publish-observation",
            &instance,
            &run_id,
            "local-observation@1",
            "--as",
            "owner",
        ];
        if let Some(at) = at {
            args.extend(["--at", at]);
        }
        let published = whip_in(&self.fixture, items, &args, None);
        if !published.status.success() {
            return Err(String::from_utf8_lossy(&published.stderr).into_owned());
        }
        let published: Value = serde_json::from_slice(&published.stdout).expect("publication JSON");
        Ok(published
            .get("event_id")
            .or_else(|| published["result"].get("event_id"))
            .and_then(Value::as_str)
            .expect("the published observation")
            .to_owned())
    }

    /// Run Q0 on `cut`, settle the run on both hosts, and publish what it
    /// observed. `tamper` edits the executor receipt's body first.
    fn observe_with(
        &self,
        cut: &str,
        run: &str,
        shape: Run<'_>,
        tamper: impl FnOnce(&mut Value),
    ) -> Result<String, String> {
        let prepared = self.prepare(cut, run);
        let mut receipt = self.receipt(&prepared, &shape);
        tamper(&mut receipt.body);
        self.journal(&prepared, &receipt, shape.failed, run, &[&self.hosted]);
        self.publish(&self.items(), run, None)
    }

    /// Run Q0 with `wrong` cases failing, exiting as a failing run does.
    fn observe(&self, cut: &str, run: &str, wrong: &[&str]) -> String {
        self.observe_with(
            cut,
            run,
            Run {
                only: None,
                wrong,
                failed: !wrong.is_empty(),
            },
            |_| {},
        )
        .expect("the observation publishes")
    }

    /// `norm impact` against the ledger at `items`.
    fn planned_in(&self, items: &Path, before: &str, after: &str) -> Value {
        let output = whip_in(
            &self.fixture,
            items,
            &["--json", "norm", "impact", before, after],
            self.host.configured(),
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let planned: Value = serde_json::from_slice(&output.stdout).expect("impact JSON");
        if planned.get("plan").is_some() {
            planned
        } else {
            planned["result"].clone()
        }
    }

    /// The impact answer from each host: native first, then the hosted
    /// object brought up to the native ledger.
    fn planned(&self, before: &str, after: &str) -> [Value; 2] {
        self.hosted.sync(&self.fixture);
        [
            self.planned_in(&self.items(), before, after),
            self.hosted.planned(before, after),
        ]
    }

    /// Promote `work` onto Main on both hosts; each refuses, and neither
    /// mainline moves. Returns each refusal's detail.
    fn refused(&self, promotion: &str) -> [Value; 2] {
        self.hosted.sync(&self.fixture);
        let native = whip_in(
            &self.fixture,
            &self.items(),
            &["stream", "promote", "work"],
            self.host.configured(),
        );
        assert!(
            !native.status.success(),
            "the mainline moved: {}",
            String::from_utf8_lossy(&native.stdout)
        );
        let native: Value = serde_json::from_slice(&native.stdout).expect("refusal JSON");
        let hosted = self.hosted.promote(promotion);
        assert!(hosted.get("promoted").is_none(), "{hosted}");
        assert_eq!(
            self.read(MAINLINE_BRANCH_ID, "src/parser.py"),
            Some(demo("src/parser.py"))
        );
        assert_eq!(
            self.hosted.read(MAINLINE_BRANCH_ID, "src/parser.py"),
            Some(demo("src/parser.py"))
        );
        [native["detail"].clone(), hosted["detail"].clone()]
    }

    /// The history of the ledger at `items`, and its pinned checkpoint.
    fn history(&self, items: &Path) -> (NormCheckpoint, Vec<TrackerEvent>) {
        with_view(&self.fixture, items, |ledger, _, _| {
            (
                ledger
                    .norm_checkpoint()
                    .expect("checkpoint")
                    .expect("pinned"),
                ledger.export_events().expect("history"),
            )
        })
    }

    /// A native replica of the ledger at `name`, pinned to `checkpoint`
    /// and holding `events`.
    fn replica(&self, name: &str, checkpoint: &NormCheckpoint, events: &[TrackerEvent]) -> PathBuf {
        let path = self.fixture.root.join(name);
        WorkItemStore::open(&path)
            .expect("replica")
            .pin_norm_checkpoint(checkpoint)
            .expect("independent pin");
        self.import(&path, events);
        path
    }

    /// Import `events` into the native ledger at `items`; how many were new.
    fn import(&self, items: &Path, events: &[TrackerEvent]) -> usize {
        with_verifier(&self.fixture, |verifier| {
            WorkItemStore::open(items)
                .expect("replica")
                .import_norm_events(events, verifier)
                .expect("the replica admits the history")
        })
    }

    /// The records of one vocabulary in a snapshot.
    fn records(snapshot: &Value, vocabulary: &str) -> Vec<Value> {
        snapshot["records"]
            .as_array()
            .expect("records")
            .iter()
            .map(|entry| entry["record"].clone())
            .filter(|record| record["vocabulary"]["name"] == vocabulary)
            .collect()
    }
}

/// R0's single impact entry in a plan.
fn impact<'a>(planned: &'a Value, requirement: &str) -> &'a Value {
    let impacts = planned["plan"]["requirements"][requirement]
        .as_array()
        .unwrap_or_else(|| panic!("{requirement} has no impact in {planned}"));
    assert_eq!(impacts.len(), 1, "{planned}");
    &impacts[0]
}

/// A JSON array of strings, as a set.
fn ids(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("not an array: {value}"))
        .iter()
        .map(|id| id.as_str().expect("an identifier").to_owned())
        .collect()
}

fn set<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
    items.into_iter().map(str::to_owned).collect()
}

/// Every key or string value in `value` with a word that labels proof or an
/// epistemic mode. (`provenance` is not one: it names where a run came from.)
fn proof_labels(value: &Value) -> Vec<String> {
    const LABELS: [&str; 6] = [
        "proof",
        "proofs",
        "proven",
        "proved",
        "epistemic",
        "universal",
    ];
    let labelled = |text: &str| {
        text.to_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| LABELS.contains(&word))
    };
    let mut found = Vec::new();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(fields) => {
                for (key, field) in fields {
                    if labelled(key) {
                        found.push(key.clone());
                    }
                    pending.push(field);
                }
            }
            Value::Array(items) => pending.extend(items),
            Value::String(text) if labelled(text) => found.push(text.clone()),
            _ => {}
        }
    }
    found
}

/// Rewrite one field of the adapter header in a receipt body's stdout.
fn retarget_header(body: &mut Value, field: &str, value: &str) {
    let stdout = body["stdout"].as_str().expect("stdout").to_owned();
    let mut lines: Vec<String> = stdout.lines().map(str::to_owned).collect();
    let mut header: Value = serde_json::from_str(&lines[0]).expect("adapter header");
    assert_eq!(header["kind"], "started");
    header[field] = json!(value);
    lines[0] = header.to_string();
    body["stdout"] = json!(format!("{}\n", lines.join("\n")));
}

/// NP-03: Q0 on A0 with complete provenance and all four cases is adequate
/// tested support, and current conformance is satisfied, on both hosts. No
/// part of either answer labels it proof: the only support kind the plan
/// carries is the tested judgment's outcome and the work it leaves.
#[test]
fn np03_tested_support_over_all_four_cases_is_never_labelled_proof() {
    let world = World::new();
    let observation = world.observe("a0", "a0", &[]);
    let answers = world.planned("a0", "a0");
    for planned in &answers {
        let impact = impact(planned, &world.requirement);
        assert_eq!(impact["work"], json!({"kind": "supported"}), "{impact}");
        let selection = &impact["selection"];
        assert_eq!(selection["conformance"], "satisfied");
        assert_eq!(ids(&selection["positive"]), set([observation.as_str()]));
        assert!(ids(&selection["counterevidence"]).is_empty());
        assert!(ids(&selection["unresolved"]).is_empty());
        let judgment = &selection["judgments"][&observation];
        assert_eq!(judgment["outcome"], "pass", "{judgment}");
        assert_eq!(ids(&judgment["required"]), set(CASES));
        assert_eq!(ids(&judgment["exercised"]), set(CASES));
        assert_eq!(judgment["counterexamples"], json!([]));
        assert_eq!(judgment["diagnostics"], json!([]));
        let report = &selection["history"][&observation]["payload"]["report"];
        assert_eq!(report["completion"], "complete", "{report}");
        assert_eq!(report["termination"], "success");
        assert_eq!(report["provenance"]["kind"], "interpreted");
        // No key or value anywhere in the answer names proof.
        assert_eq!(proof_labels(planned), Vec::<String>::new(), "{planned}");
    }
    assert_eq!(
        impact(&answers[0], &world.requirement)["selection"]["judgments"],
        impact(&answers[1], &world.requirement)["selection"]["judgments"]
    );
    // Nor the published observation as the ledger holds it, on either host.
    let native = world.fixture.run(&["snapshot"])["result"]["snapshot"].clone();
    let hosted = world
        .hosted
        .command(json!({"kind": "snapshot"}))
        .expect("hosted snapshot")["snapshot"]
        .clone();
    for snapshot in [native, hosted] {
        let observations = World::records(&snapshot, "local-observation");
        assert_eq!(observations.len(), 1, "{snapshot}");
        let recorded = observations[0]["fields"]["observation_json"]
            .as_str()
            .expect("observation")
            .to_lowercase();
        assert!(recorded.contains("\"outcome\":\"pass\""), "{recorded}");
        let recorded: Value = serde_json::from_str(&recorded).expect("observation JSON");
        assert_eq!(proof_labels(&recorded), Vec::<String>::new(), "{recorded}");
    }
}

/// NP-04: a filter that exercises zero cases, a truncated report and a
/// missing report are each a harness failure with its own diagnostic. None
/// is positive support, and gated admission refuses on both hosts.
#[test]
fn np04_zero_case_truncated_and_missing_reports_are_distinct_refused_harness_failures() {
    let world = World::new();
    world.line("src/parser.py", REPAIRED, "a1", "t3");
    // A filter that selects nothing: the adapter runs, completes, and
    // observes no case.
    let zero = world
        .observe_with(
            "a1",
            "zero",
            Run {
                only: Some(&[]),
                ..PASSING
            },
            |_| {},
        )
        .expect("a zero-case report publishes");
    // Every case observed, but the executor's stream was cut off.
    let truncated = world
        .observe_with("a1", "truncated", PASSING, |body| {
            body["stdout_truncated"] = json!(true)
        })
        .expect("a truncated report publishes");
    // No report at all: nothing binds the run, and neither host will
    // publish it as an observation.
    let missing = world
        .observe_with("a1", "missing", PASSING, |body| body["stdout"] = json!(""))
        .expect_err("a missing report is not an observation");
    assert!(missing.contains("no bound observer header"), "{missing}");
    // The hosted publication door would publish the zero-case run (it was
    // prepared before either publication), and refuses the missing report.
    world
        .hosted
        .prepare_publication("zero")
        .expect("the hosted door publishes a bound harness failure");
    world.hosted.sync(&world.fixture);
    let hosted_missing = world
        .hosted
        .prepare_publication("missing")
        .expect_err("the hosted door refuses it too");
    assert!(
        hosted_missing.contains("no bound observer header"),
        "{hosted_missing}"
    );

    let answers = world.planned("a0", "a1");
    for planned in &answers {
        let impact = impact(planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "check", "{impact}");
        let selection = &impact["selection"];
        assert!(ids(&selection["positive"]).is_empty(), "{selection}");
        assert!(ids(&selection["counterevidence"]).is_empty());
        assert_eq!(
            ids(&selection["unresolved"]),
            set([zero.as_str(), truncated.as_str()])
        );
        // Zero cases: every required case is missing, and nothing says the
        // report itself was cut short.
        let judgment = &selection["judgments"][&zero];
        assert_eq!(judgment["outcome"], "harness_failed");
        assert!(ids(&judgment["exercised"]).is_empty());
        assert_eq!(
            judgment["diagnostics"],
            json!(CASES
                .iter()
                .map(|case| json!({"kind": "missing_case", "detail": case}))
                .collect::<Vec<_>>()),
            "{judgment}"
        );
        // Truncated: every case exercised, and the report diagnosed as cut
        // short, not as missing cases.
        let judgment = &selection["judgments"][&truncated];
        assert_eq!(judgment["outcome"], "harness_failed");
        assert_eq!(ids(&judgment["exercised"]), set(CASES));
        assert_eq!(
            judgment["diagnostics"],
            json!([{"kind": "truncated_report"}]),
            "{judgment}"
        );
        // One investigation for the method on this artifact, naming both.
        let investigations = planned["investigations"]
            .as_array()
            .expect("investigations");
        assert_eq!(investigations.len(), 1, "{planned}");
        assert_eq!(investigations[0]["harness_failed"], true);
        assert_eq!(investigations[0]["suspect"], false);
        assert_eq!(
            ids(&investigations[0]["observations"]),
            set([zero.as_str(), truncated.as_str()])
        );
    }
    assert_eq!(answers[0]["investigations"], answers[1]["investigations"]);
    for detail in world.refused("harness-failed") {
        assert_eq!(
            detail["requirements"][&world.requirement],
            json!(["check"]),
            "{detail}"
        );
    }
}

/// NP-04: the investigation a harness failure calls for is filed once. Filing
/// it under its nonce again, re-signing it, replaying the view, and importing
/// the same history again leave one issue on each host.
#[test]
fn np04_an_investigation_filed_under_its_nonce_is_one_issue_however_it_is_replayed() {
    let world = World::new();
    world.line("src/parser.py", REPAIRED, "a1", "t3");
    world
        .observe_with(
            "a1",
            "zero",
            Run {
                only: Some(&[]),
                ..PASSING
            },
            |_| {},
        )
        .expect("a zero-case report publishes");
    let [native, hosted] = world.planned("a0", "a1");
    assert_eq!(native["investigations"], hosted["investigations"]);
    let investigation = native["investigations"][0].clone();
    let nonce = investigation["nonce"].as_str().expect("nonce").to_owned();
    assert!(nonce.starts_with("investigate-"), "{investigation}");

    // File it: the owner's issue, under the investigation's nonce.
    world.fixture.write(
        "issue.json",
        &json!({
            "title": "Investigate Q0's harness failure",
            "body": format!(
                "{} on {}",
                investigation["method"]["digest"].as_str().expect("method"),
                investigation["artifact"].as_str().expect("artifact")
            ),
        }),
    );
    let file = |at: &str| {
        world.fixture.command(&[
            "create",
            "issue@1",
            "--as",
            "owner",
            "--fields",
            "issue.json",
            "--nonce",
            &nonce,
            "--at",
            at,
        ])
    };
    let filed = |at: &str| {
        let output = file(at).output().expect("filing");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).expect("filing JSON")["result"]["event_id"]
            .as_str()
            .expect("the issue")
            .to_owned()
    };
    let issue = filed("2026-09-28T00:00:00Z");
    // A retry of the same filing is the same event.
    assert_eq!(filed("2026-09-28T00:00:00Z"), issue);
    // Filing it again, freshly signed, under the same nonce is refused.
    let again = file("2026-09-28T01:00:00Z").output().expect("filing");
    assert!(!again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("nonce was already admitted"),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let exported = world.fixture.run(&["export"])["result"]["events"].clone();
    let count = exported.as_array().expect("events").len();

    // Replaying the view files nothing, and asks for the same nonce.
    for planned in world.planned("a0", "a1") {
        assert_eq!(planned["investigations"][0]["nonce"], nonce.as_str());
    }
    assert_eq!(
        world.fixture.run(&["export"])["result"]["events"]
            .as_array()
            .expect("events")
            .len(),
        count
    );
    // Importing the same history again inserts nothing, on either host.
    world.fixture.write("history.json", &exported);
    assert_eq!(
        world.fixture.run(&["import", "--events", "history.json"])["result"]["inserted"],
        0
    );
    let hosted_again = world.hosted.sync(&world.fixture);
    assert_eq!(hosted_again["inserted"], 0, "{hosted_again}");

    // The re-signed filing, as another client would submit it, is refused
    // by both hosts' doors.
    let statement = exported
        .as_array()
        .expect("events")
        .iter()
        .find(|event| event["event_id"] == issue.as_str())
        .map(|event| {
            let signed: Value =
                serde_json::from_str(event["payload_json"].as_str().expect("payload"))
                    .expect("signed event");
            let mut statement = signed["statement"].clone();
            statement["created_at"] = json!("2026-09-28T02:00:00Z");
            statement
        })
        .expect("the filed issue");
    world.fixture.write("statement.json", &statement);
    let resigned = world
        .fixture
        .run(&["sign", "--as", "owner", "--statement", "statement.json"]);
    let append = json!({"kind": "append", "event": resigned});
    world.fixture.write(
        "append.json",
        &json!({"protocol": "whipplescript.norm.commands/v1", "command": append}),
    );
    world
        .fixture
        .refuse(&["dispatch", "--request", "append.json"]);
    let hosted_refusal = world
        .hosted
        .command(append)
        .expect_err("the hosted door refuses the re-signed filing");
    assert!(
        hosted_refusal.contains("nonce was already admitted"),
        "{hosted_refusal}"
    );

    // One issue on each host.
    let native = world.fixture.run(&["snapshot"])["result"]["snapshot"].clone();
    let hosted = world
        .hosted
        .command(json!({"kind": "snapshot"}))
        .expect("hosted snapshot")["snapshot"]
        .clone();
    for snapshot in [native, hosted] {
        let issues = World::records(&snapshot, "issue");
        assert_eq!(issues.len(), 1, "{snapshot}");
        assert_eq!(issues[0]["id"], issue.as_str());
    }
}

/// NP-05: a wrapper runs the negative mutation and exits zero despite
/// worker-deny's failure. Neither host takes it as positive support: the
/// inconsistent termination is diagnosed, the counterexample is retained as
/// counterevidence, and gated admission refuses for repair.
#[test]
fn np05_a_zero_exit_over_the_worker_deny_failure_is_diagnosed_and_keeps_its_counterexample() {
    let world = World::new();
    let a0 = world.observe("a0", "a0", &[]);
    world.line("src/parser.py", MUTATED, "a1", "t3");
    let swallowed = world
        .observe_with(
            "a1",
            "swallowed",
            Run {
                only: None,
                wrong: &["worker-deny"],
                failed: false,
            },
            |_| {},
        )
        .expect("the swallowed failure publishes");
    let answers = world.planned("a0", "a1");
    for planned in &answers {
        let impact = impact(planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "repair", "{impact}");
        let selection = &impact["selection"];
        assert_eq!(selection["conformance"], "violated");
        assert!(ids(&selection["positive"]).is_empty(), "{selection}");
        assert_eq!(
            ids(&selection["counterevidence"]),
            set([swallowed.as_str()])
        );
        assert_eq!(ids(&selection["unresolved"]), set([swallowed.as_str()]));
        assert_eq!(ids(&selection["stale"]), set([a0.as_str()]));
        let report = &selection["history"][&swallowed]["payload"]["report"];
        assert_eq!(report["termination"], "success", "{report}");
        let judgment = &selection["judgments"][&swallowed];
        assert_eq!(judgment["outcome"], "harness_failed");
        assert_eq!(ids(&judgment["exercised"]), set(CASES));
        assert_eq!(
            judgment["diagnostics"],
            json!([{"kind": "inconsistent_termination"}]),
            "{judgment}"
        );
        let counterexamples = judgment["counterexamples"]
            .as_array()
            .expect("counterexamples");
        assert_eq!(counterexamples.len(), 1, "{judgment}");
        assert_eq!(counterexamples[0]["case"], "worker-deny");
        assert_eq!(counterexamples[0]["expected"], false);
        assert_eq!(counterexamples[0]["actual"], true);
        assert!(!counterexamples[0]["witness"]
            .as_str()
            .expect("witness")
            .is_empty());
    }
    assert_eq!(
        impact(&answers[0], &world.requirement)["selection"]["judgments"][&swallowed],
        impact(&answers[1], &world.requirement)["selection"]["judgments"][&swallowed]
    );
    for detail in world.refused("swallowed") {
        assert_eq!(
            detail["requirements"][&world.requirement],
            json!(["repair"]),
            "{detail}"
        );
    }
}

/// NP-06: a change outside the requirement's domain leaves its protected
/// run's staged files, and so its tested artifact, unchanged. Q0's support
/// carries on both hosts, no check is scheduled, and the plan names the
/// ceiling and the change it carried across (DR-0133).
#[test]
fn np06_a_change_outside_the_ceiling_reuses_support_and_names_its_witness() {
    let world = World::new();
    let a0 = world.observe("a0", "a0", &[]);
    world.line(
        "README.md",
        "# The authorization demo, edited\n",
        "a1",
        "t3",
    );
    for planned in world.planned("a0", "a1") {
        let impact = impact(&planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "supported", "{impact}");
        assert_eq!(ids(&impact["selection"]["positive"]), set([a0.as_str()]));
        assert_eq!(
            impact["ceiling"],
            json!({"domain": "authorization", "outside": ["README.md"]}),
            "{impact}"
        );
    }
}

/// NP-08: configuration outside the declared domain is never staged, so a
/// protected run cannot read it and reusing its support is sound. Where the
/// domain itself changes, a fresh run that leaves a premise unestablished
/// keeps admission unresolved on both hosts. (A partial observer, whose
/// reads nothing encloses, is never support in production: the protected
/// policy accepts only protected observations.)
#[test]
fn np08_configuration_outside_the_declared_domain_is_never_staged_and_unestablished_premises_stay_unresolved(
) {
    let world = World::new();
    let a0 = world.observe("a0", "a0", &[]);
    let domain = &world
        .charter
        .resource_domains
        .as_ref()
        .expect("C0 declares its domains")["authorization"];
    assert!(
        !serde_json::to_string(domain)
            .expect("domain")
            .contains("\"deploy\""),
        "{domain:?}"
    );
    world.line(
        "deploy/override.toml",
        "default_grant = \"allow\"\n",
        "a1",
        "t3",
    );
    let staged = world.prepare("a1", "staged");
    let files = staged.request().body["stdin"]["files"]
        .as_object()
        .expect("the run's staged files")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(files.contains("src/auth.py"), "{files:?}");
    assert!(!files.contains("deploy/override.toml"), "{files:?}");
    assert!(!files.contains("README.md"), "{files:?}");
    for planned in world.planned("a0", "a1") {
        let impact = impact(&planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "supported", "{impact}");
        assert_eq!(ids(&impact["selection"]["positive"]), set([a0.as_str()]));
        assert_eq!(
            impact["ceiling"]["outside"],
            json!(["deploy/override.toml"]),
            "{impact}"
        );
    }

    // Inside the domain, a new configuration file invalidates the support,
    // and a fresh run that observes three cases does not establish coverage.
    world.line("config/strict.toml", "strict = true\n", "a2", "t4");
    let partial = world
        .observe_with(
            "a2",
            "partial",
            Run {
                only: Some(&["owner-allow", "owner-deny", "worker-allow"]),
                ..PASSING
            },
            |_| {},
        )
        .expect("a partial report publishes");
    // A run whose report names another artifact binds to nothing, and
    // neither host publishes it.
    let foreign = world
        .observe_with("a2", "foreign", PASSING, |body| {
            retarget_header(body, "artifact", &"f".repeat(64))
        })
        .expect_err("a report of another artifact is not an observation");
    assert!(foreign.contains("no bound observer header"), "{foreign}");
    world.hosted.sync(&world.fixture);
    let hosted_foreign = world
        .hosted
        .prepare_publication("foreign")
        .expect_err("the hosted door refuses it too");
    assert!(
        hosted_foreign.contains("no bound observer header"),
        "{hosted_foreign}"
    );
    for planned in world.planned("a0", "a2") {
        let impact = impact(&planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "check", "{impact}");
        let selection = &impact["selection"];
        assert!(ids(&selection["positive"]).is_empty(), "{selection}");
        assert_eq!(ids(&selection["stale"]), set([a0.as_str()]));
        assert_eq!(ids(&selection["unresolved"]), set([partial.as_str()]));
        assert_eq!(
            selection["judgments"][&partial]["diagnostics"],
            json!([{"kind": "missing_case", "detail": "worker-deny"}])
        );
    }
    for detail in world.refused("inside-domain") {
        assert_eq!(
            detail["requirements"][&world.requirement],
            json!(["check"]),
            "{detail}"
        );
    }
}

/// NP-09: creating a previously absent optional configuration file under
/// the domain invalidates Q0's support on both hosts, though the subject's
/// bytes are unchanged.
#[test]
fn np09_creating_an_absent_optional_configuration_file_invalidates_support() {
    let world = World::new();
    let a0 = world.observe("a0", "a0", &[]);
    for planned in world.planned("a0", "a0") {
        assert_eq!(
            impact(&planned, &world.requirement)["work"]["kind"],
            "supported"
        );
    }
    assert_eq!(world.read("line-work", "config/optional.toml"), None);
    assert_eq!(world.hosted.read("line-work", "config/optional.toml"), None);
    world.line("config/optional.toml", "strict = true\n", "a1", "t3");
    assert_eq!(
        world.read("line-work", "src/auth.py"),
        Some(demo("src/auth.py"))
    );
    assert_eq!(
        world.hosted.read("line-work", "src/auth.py"),
        Some(demo("src/auth.py"))
    );
    for planned in world.planned("a0", "a1") {
        let impact = impact(&planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "check", "{impact}");
        assert!(ids(&impact["selection"]["positive"]).is_empty());
        assert_eq!(ids(&impact["selection"]["stale"]), set([a0.as_str()]));
    }
    for detail in world.refused("optional-config") {
        assert_eq!(
            detail["requirements"][&world.requirement],
            json!(["check"]),
            "{detail}"
        );
    }
}

/// NP-09: on the same cut, a changed method definition and then a changed
/// interpreter each turn Q0's support into a planned check on both hosts,
/// naming a method other than the one that supported it. An interpreter
/// installed before R0 is re-pinned to it supports nothing either.
#[test]
fn np09_method_and_interpreter_changes_turn_support_into_a_check_on_both_hosts() {
    let mut world = World::new();
    let method_of = |planned: &Value, observation: &str| {
        impact(planned, &world.requirement)["selection"]["judgments"][observation]["subject"]
            ["method"]
            .clone()
    };
    let first = world.observe("a0", "a0", &[]);
    let supported = world.planned("a0", "a0");
    let original = method_of(&supported[0], &first);
    for planned in &supported {
        assert_eq!(
            impact(planned, &world.requirement)["work"]["kind"],
            "supported"
        );
    }
    let revise = |world: &World, support: String| {
        world
            .fixture
            .write("r0-revised.json", &requirement_fields(&support));
        world.fixture.run(&[
            "edit",
            &world.requirement,
            "--as",
            "owner",
            "--fields",
            "r0-revised.json",
        ]);
        world.fixture.run(&[
            "transition",
            &world.requirement,
            "accepted",
            "--as",
            "owner",
        ]);
    };

    // The method: Q0's cases pass their inputs by name.
    revise(&world, support(&world.host.runtime, true));
    let method_changed = world.planned("a0", "a0");
    for planned in &method_changed {
        let impact = impact(planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "check", "{impact}");
        assert_ne!(impact["work"]["method"], original, "{impact}");
        assert!(ids(&impact["selection"]["positive"]).is_empty());
        assert!(ids(&impact["selection"]["excluded"]).contains(&first));
    }
    assert_eq!(
        impact(&method_changed[0], &world.requirement)["work"],
        impact(&method_changed[1], &world.requirement)["work"]
    );
    let second = world.observe("a0", "a0-by-name", &[]);
    let resupported = world.planned("a0", "a0");
    let by_name = method_of(&resupported[0], &second);
    assert_eq!(
        impact(&method_changed[0], &world.requirement)["work"]["method"],
        by_name
    );
    for planned in &resupported {
        assert_eq!(
            impact(planned, &world.requirement)["work"]["kind"],
            "supported"
        );
    }

    // The interpreter: another protected CPython build. Installed alone,
    // while R0 still pins the previous one, it supports nothing.
    let mut interpreter = world.host.runtime.clone();
    interpreter.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/reactor.wasm".into(),
        artifact_sha256: "d".repeat(64),
    };
    world.host = Host::install(&world.fixture, &world.charter, interpreter);
    world.hosted.redeploy(&world.host);
    for planned in world.planned("a0", "a0") {
        let impact = impact(&planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "observation_gap", "{impact}");
        assert!(ids(&impact["selection"]["positive"]).is_empty());
        assert!(planned["method_gaps"][&world.requirement][0]["reason"]
            .as_str()
            .is_some());
    }
    // R0 re-pinned to it: support becomes a check under the new method.
    revise(&world, support(&world.host.runtime, true));
    let interpreter_changed = world.planned("a0", "a0");
    for planned in &interpreter_changed {
        let impact = impact(planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "check", "{impact}");
        assert_ne!(impact["work"]["method"], by_name, "{impact}");
        assert_ne!(impact["work"]["method"], original, "{impact}");
        assert!(ids(&impact["selection"]["positive"]).is_empty());
    }
    assert_eq!(
        impact(&interpreter_changed[0], &world.requirement)["work"],
        impact(&interpreter_changed[1], &world.requirement)["work"]
    );
}

/// NP-09: a run whose adapter differs from the one the host installs, with
/// the same subject bytes, method definition and interpreter, is not
/// support. Its report binds to nothing, neither host publishes it, and the
/// plan still asks for a check; the installed adapter's run then supports.
#[test]
fn np09_a_run_under_another_adapter_supports_nothing_on_either_host() {
    let world = World::new();
    let other = whipplescript_kernel::exec_http::sha256_hex(b"another adapter");
    let refused = world
        .observe_with("a0", "other-adapter", PASSING, |body| {
            retarget_header(body, "adapter_digest", &other)
        })
        .expect_err("another adapter's report is not an observation");
    assert!(refused.contains("no bound observer header"), "{refused}");
    let hosted_refused = world
        .hosted
        .prepare_publication("other-adapter")
        .expect_err("the hosted door refuses it too");
    assert!(
        hosted_refused.contains("no bound observer header"),
        "{hosted_refused}"
    );
    for planned in world.planned("a0", "a0") {
        let impact = impact(&planned, &world.requirement);
        assert_eq!(impact["work"]["kind"], "check", "{impact}");
        assert!(ids(&impact["selection"]["positive"]).is_empty());
    }
    world.observe("a0", "installed-adapter", &[]);
    for planned in world.planned("a0", "a0") {
        assert_eq!(
            impact(&planned, &world.requirement)["work"]["kind"],
            "supported"
        );
    }
}

/// NP-11: two replicas of the ledger each publish one run of Q0 on A1 from
/// the same frontier, one passing and one failing at worker-deny, the pass
/// stamped later. Folded natively and on hosted objects, in either import
/// order, every fold holds the same conflict with the same supporting
/// witnesses: no order, and no clock, selects a winner.
#[test]
fn np11_concurrent_pass_and_fail_fold_to_the_same_conflict_in_either_order() {
    let world = World::new();
    world.line("src/parser.py", REPAIRED, "a1", "t3");
    let folds_hosted = [Hosted::new(&world.host), Hosted::new(&world.host)];
    for hosted in &folds_hosted {
        hosted.write("line-work", "src/parser.py", REPAIRED, "a1", "t3");
    }
    let (checkpoint, base) = world.history(&world.items());
    let peers = [
        world.replica("peer-pass.sqlite", &checkpoint, &base),
        world.replica("peer-fail.sqlite", &checkpoint, &base),
    ];
    let targets: Vec<&Hosted> = folds_hosted.iter().collect();
    for (run, wrong) in [("pass", &[][..]), ("fail", &["worker-deny"][..])] {
        let prepared = world.prepare("a1", run);
        let shape = Run {
            only: None,
            wrong,
            failed: !wrong.is_empty(),
        };
        let receipt = world.receipt(&prepared, &shape);
        world.journal(&prepared, &receipt, shape.failed, run, &targets);
    }
    let pass = world
        .publish(&peers[0], "pass", Some("2026-09-28T00:00:02Z"))
        .expect("the pass publishes on its replica");
    let fail = world
        .publish(&peers[1], "fail", Some("2026-09-28T00:00:01Z"))
        .expect("the failure publishes on its replica");
    let from = |peer: &Path| world.history(peer).1;
    let (passing, failing) = (from(&peers[0]), from(&peers[1]));
    let parents = |events: &[TrackerEvent], id: &str| {
        events
            .iter()
            .find(|event| event.event_id == id)
            .expect("the publication")
            .parents
            .clone()
    };
    // Concurrent: each was published on the same frontier, without the other.
    assert_eq!(parents(&passing, &pass), parents(&failing, &fail));
    assert!(!passing.iter().any(|event| event.event_id == fail));
    assert!(!failing.iter().any(|event| event.event_id == pass));

    let pass_first = world.replica("fold-pass-first.sqlite", &checkpoint, &passing);
    assert_eq!(world.import(&pass_first, &failing), 1);
    let fail_first = world.replica("fold-fail-first.sqlite", &checkpoint, &failing);
    assert_eq!(world.import(&fail_first, &passing), 1);
    folds_hosted[0].import(&checkpoint, &passing);
    folds_hosted[0].import(&checkpoint, &failing);
    folds_hosted[1].import(&checkpoint, &failing);
    folds_hosted[1].import(&checkpoint, &passing);
    let folds = [
        world.planned_in(&pass_first, "a0", "a1"),
        world.planned_in(&fail_first, "a0", "a1"),
        folds_hosted[0].planned("a0", "a1"),
        folds_hosted[1].planned("a0", "a1"),
    ];
    let witnesses = |planned: &Value| {
        let impact = impact(planned, &world.requirement);
        let selection = &impact["selection"];
        json!({
            "work": impact["work"],
            "conformance": selection["conformance"],
            "positive": selection["positive"],
            "counterevidence": selection["counterevidence"],
            "unresolved": selection["unresolved"],
            "retired_by": selection["retired_by"],
            "judgments": selection["judgments"],
            "investigations": planned["investigations"],
        })
    };
    let first = witnesses(&folds[0]);
    assert_eq!(first["work"]["kind"], "resolve_evidence", "{first}");
    assert_eq!(first["conformance"], "conflicted");
    assert_eq!(ids(&first["positive"]), set([pass.as_str()]));
    assert_eq!(ids(&first["counterevidence"]), set([fail.as_str()]));
    assert_eq!(first["retired_by"], json!({}));
    assert_eq!(first["judgments"][&pass]["outcome"], "pass");
    assert_eq!(first["judgments"][&fail]["outcome"], "fail");
    assert_eq!(
        first["judgments"][&fail]["counterexamples"][0]["case"],
        "worker-deny"
    );
    let investigations = first["investigations"].as_array().expect("investigations");
    assert_eq!(investigations.len(), 1, "{first}");
    assert_eq!(investigations[0]["suspect"], true);
    assert_eq!(
        ids(&investigations[0]["observations"]),
        set([pass.as_str(), fail.as_str()])
    );
    for (index, fold) in folds.iter().enumerate() {
        assert_eq!(witnesses(fold), first, "fold {index}");
    }
    // The gate of a fold refuses to pick either.
    for hosted in &folds_hosted {
        let refusal = hosted.promote("conflicted");
        assert_eq!(
            refusal["detail"]["requirements"][&world.requirement],
            json!(["resolve_evidence"]),
            "{refusal}"
        );
    }
}

/// Every non-ledger table of a hosted object, as the workerd harness seeds
/// it: each table's rows by column, and the DDL that created it, for a table
/// the Worker's object has not created yet. The ledger (`tracker_*`) is left
/// out: the Worker takes it through its own import door.
fn hosted_tables(sql: &RusqliteDoSql) -> BTreeMap<String, Value> {
    use whipplescript_host_do::do_store::{DoSql, SqlValue};
    let text = |value: &SqlValue| match value {
        SqlValue::Text(text) => text.clone(),
        other => panic!("{other:?} is not text"),
    };
    let mut tables = BTreeMap::new();
    for row in sql
        .query(
            "SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name",
            &[],
        )
        .expect("tables")
    {
        let table = text(&row[0]);
        if table.starts_with("tracker_")
            || table.starts_with("sqlite_")
            || table == "schema_migrations"
        {
            continue;
        }
        let mut ddl = vec![text(&row[1])];
        for index in sql
            .query(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ?1 AND sql IS NOT NULL ORDER BY name",
                &[SqlValue::Text(table.clone())],
            )
            .expect("indexes")
        {
            ddl.push(text(&index[0]));
        }
        let columns: Vec<String> = sql
            .query(&format!("PRAGMA table_info(\"{table}\")"), &[])
            .expect("columns")
            .iter()
            .map(|column| text(&column[1]))
            .collect();
        let rows: Vec<Value> = sql
            .query(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"), &[])
            .expect("rows")
            .iter()
            .map(|row| {
                json!(row
                    .iter()
                    .map(|value| match value {
                        SqlValue::Null => Value::Null,
                        SqlValue::Int(n) => json!(n),
                        SqlValue::Text(s) => json!(s),
                    })
                    .collect::<Vec<_>>())
            })
            .collect();
        tables.insert(
            table.clone(),
            json!({"table": table, "ddl": ddl, "columns": columns, "rows": rows}),
        );
    }
    tables
}

/// The hosted promotion route's workerd vector (WS-115): the demo's governed
/// object with R0 accepted and W's repair of the parser on `work`, first with
/// no support at the candidate and then with Q0's passing run settled in the
/// object's journal and published. The hosted door refuses the first naming
/// R0 and admits the second; the Worker must answer both exactly as this door
/// did, over rows and history this door's own codecs wrote.
#[test]
fn norm_cli_promotion_vector_refuses_unsupported_and_admits_supported_candidates() {
    let world = World::new();
    world.line("src/parser.py", REPAIRED, "a1", "t3");
    let unsupported_tables = hosted_tables(&world.hosted.sql);
    let (checkpoint, unsupported_events) = world.history(&world.items());

    let refused = world.hosted.promote("unsupported");
    assert_eq!(refused["refused"], "work", "{refused}");
    assert_eq!(
        refused["detail"]["requirements"][&world.requirement],
        json!(["check"]),
        "{refused}"
    );
    assert_eq!(
        world.hosted.read(MAINLINE_BRANCH_ID, "src/parser.py"),
        Some(demo("src/parser.py"))
    );

    world.observe("a1", "a1", &[]);
    let supported_tables = hosted_tables(&world.hosted.sql);
    let (_, supported_events) = world.history(&world.items());
    world.hosted.sync(&world.fixture);
    // Only the settled run's journal is new: the rows its observation needs,
    // with nothing the refused promotion wrote.
    let journal: Vec<Value> = supported_tables
        .values()
        .filter(|table| {
            table["columns"]
                .as_array()
                .expect("columns")
                .iter()
                .any(|column| column == "instance_id")
        })
        .filter_map(|table| {
            let before = unsupported_tables
                .get(table["table"].as_str().expect("table"))
                .map(|before| before["rows"].as_array().expect("rows").clone())
                .unwrap_or_default();
            let rows: Vec<Value> = table["rows"]
                .as_array()
                .expect("rows")
                .iter()
                .filter(|row| !before.contains(row))
                .cloned()
                .collect();
            (!rows.is_empty()).then(|| {
                json!({"table": table["table"], "ddl": table["ddl"], "columns": table["columns"], "rows": rows})
            })
        })
        .collect();
    assert!(
        !journal.is_empty(),
        "the run settled in the object's journal"
    );

    let admitted = world.hosted.promote("supported");
    assert_eq!(admitted["promoted"], "work", "{admitted}");
    assert_eq!(
        world
            .hosted
            .read(MAINLINE_BRANCH_ID, "src/parser.py")
            .as_deref(),
        Some(REPAIRED)
    );

    if let Ok(path) = std::env::var("WHIPPLESCRIPT_NORM_PROMOTION_VECTOR_OUT") {
        let trust: Value = serde_json::from_str(&world.hosted.trust).expect("trust");
        let deployment: Value = serde_json::from_str(&world.hosted.deployment).expect("deployment");
        std::fs::write(
            path,
            json!({
                "protocol": "whipplescript.norm.promotion-test-vector/v1",
                "public_bindings": trust["public_bindings"],
                "checkpoint": checkpoint,
                "events": unsupported_events,
                "supported_events": supported_events,
                "deployment": {
                    "planning": deployment["planning"],
                    "runtime": deployment["runtime"],
                    "image_binding": deployment["image_binding"],
                    "deployed_image": deployment["deployed_image"],
                },
                "workspace": unsupported_tables
                    .values()
                    .filter(|table| !table["rows"].as_array().expect("rows").is_empty())
                    .collect::<Vec<_>>(),
                "journal": journal,
                "requirement": world.requirement,
                "stream": "work",
                "path": "src/parser.py",
                "base": demo("src/parser.py"),
                "candidate": REPAIRED,
                "refused": refused,
                "admitted": admitted,
            })
            .to_string(),
        )
        .expect("promotion vector");
    }
}
