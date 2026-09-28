//! The norm plane's door rows over `examples/authorization-demo`, on both
//! hosts (norm-plane admission fixtures, G1/R1/S1): NP-07's invalidation
//! with the subject unchanged, NP-10's retained duties, NP-14's stale
//! certificate for every premise kind, NP-16's ungated doors, NP-17's gated
//! lines no activation can bind or release, NP-18's candidate that cannot
//! exempt itself, NP-19's inspectable repair, NP-20's merged offline claims,
//! and NP-22's folding that no intent edit establishes.
//!
//! Each row runs natively (`WorkItemStore`, `SqliteStore`,
//! `NativeWorkspaceVcs`, the `whip` CLI) and on the hosted workspace object
//! (`DoSqliteStore` over `RusqliteDoSql`, `DoBranches`, and the hosted
//! command, impact, promotion and in-language doors), and asserts the same
//! answer from both.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use whipplescript_core::norm_evidence::RequiredCase;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_custody::client::UnixSocketTransport;
use whipplescript_host_do::do_store::test_support::RusqliteDoSql;
use whipplescript_host_do::do_store::DoSqliteStore;
use whipplescript_host_do::norm_commands::{
    execute_hosted_norm_command_with_artifacts, HostedNormGate,
};
use whipplescript_kernel::effect_handlers::{CapabilityOutcome, CapabilityProvider};
use whipplescript_kernel::norm_admission::{AdmissionDoor, AdmissionHost, NormMainlineAdmission};
use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
use whipplescript_kernel::norm_execution::{
    fixtures as execution, NormRunSelection, PreparedNormExecution, PythonCallSupport,
};
use whipplescript_kernel::norm_execution_policy::ProtectedPythonPolicy;
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_kernel::norm_planning::PlanningConfiguration;
use whipplescript_kernel::norm_public_key::{NormPublicKeyBinding, NormPublicKeyVerifier};
use whipplescript_kernel::norm_runner::{
    PythonCallMethod, PythonCase, PythonEngine, PythonRuntime,
};
use whipplescript_kernel::sansio::HttpResponse;
use whipplescript_store::branches::{BindOutcome, MAINLINE_BRANCH_ID};
use whipplescript_store::items::{TrackerEvent, WorkItemStore};
use whipplescript_store::norm::{
    NormAct, NormActor, NormCharter, NormCheckpoint, NormPremises, NormStatement, NormView,
};
use whipplescript_store::norm_artifact::ArtifactLimits;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::vcs::{
    GateCommit, GateVerdict, MainlineGate, NativeWorkspaceVcs, RestoreOutcome,
};
use whipplescript_store::workstreams::{WorkstreamStore, Workstreams};
use whipplescript_store::{RuntimeStore, ScriptCapabilityRegistration, SqliteStore, StoreResult};

const MUTATED: &str = "def grant_allows(grant):\n    return grant in (\"allow\", \"deny\")\n";
const REPAIRED: &str =
    "def grant_allows(grant):\n    # Only an explicit allowing grant allows.\n    return grant == \"allow\"\n";
const STALE: &str = "the norm ledger changed after the admission was prepared";

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

/// The protected runtime the hosts install.
fn runtime() -> PythonRuntime {
    let mut method = execution::method();
    method.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/reactor.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    method.runtime.executable = "/usr/local/bin/whip".into();
    method.runtime
}

/// Q0, the demo's four-case check, over `runtime`.
fn q0(runtime: &PythonRuntime) -> (PythonCallMethod, Vec<RequiredCase>) {
    let q0: Value = serde_json::from_str(&demo("checks/q0.json")).expect("Q0");
    let cases = q0["cases"].as_array().expect("Q0 cases");
    let method = PythonCallMethod {
        runtime: runtime.clone(),
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

/// A requirement's declaration with Q0 over `runtime` as its contract.
fn requirement_fields(name: &str, runtime: &PythonRuntime) -> Value {
    let (method, cases) = q0(runtime);
    json!({
        "name": name,
        "proposition": "for role in {owner, worker} and grant in {allow, deny}, authorized iff role == owner or grant == allow",
        "domain": "authorization",
        "subject": "src/auth.py",
        "applicability": "the authorization domain",
        "owner": "owner",
        "support_contract": json!(PythonCallSupport::V1 { method, cases }).to_string(),
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
    fn install(fixture: &Fixture, charter: &NormCharter) -> Self {
        let runtime = runtime();
        let (method, required) = q0(&runtime);
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

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The fixture's principals, as a host verifies their signatures: the owner,
/// the worker, and the owner's successor key.
fn with_verifier<T>(
    fixture: &Fixture,
    read: impl FnOnce(&dyn whipplescript_store::norm::NormVerifier) -> T,
) -> T {
    let transport = UnixSocketTransport::new(fixture.root.join("custody.sock"));
    let key = |principal: &str, name: &str| {
        NormCustodyKey::new(
            principal.into(),
            CredentialName::new(&format!("norm/{name}")).expect("credential"),
            NormCustodyVersion::ImmutableLocal,
            &transport,
        )
        .expect("custody key")
    };
    let keys = [
        key("owner", "owner"),
        key("worker", "worker"),
        key("owner", "successor"),
    ];
    let verifier = NormGovernanceVerifier::new(
        keys.iter()
            .map(|key| NormPrincipalBinding {
                actor: key.actor().clone(),
                verifier: key,
            })
            .collect(),
        [("worker".into(), "owner".into())].into(),
    )
    .expect("verifier");
    read(&verifier)
}

/// The ledger at `items` as the fixture's principals signed it.
fn with_view<T>(
    fixture: &Fixture,
    items: &Path,
    read: impl FnOnce(&mut WorkItemStore, &NormView) -> T,
) -> T {
    with_verifier(fixture, |verifier| {
        let mut ledger = WorkItemStore::open(items).expect("ledger");
        let view = ledger.norm_view(verifier).expect("verified view");
        read(&mut ledger, &view)
    })
}

/// A principal as the fixture's custody signs for it.
fn actor(signer: &str) -> NormActor {
    let principal = if signer == "worker" {
        "worker"
    } else {
        "owner"
    };
    NormActor {
        principal: principal.into(),
        algorithm: "ed25519-custodian".into(),
        key_id: format!("credential:norm/{signer}#local"),
    }
}

/// A hosted workspace object: its own branches, content and runtime journal,
/// a ledger imported through the hosted command door under deployment trust
/// (which binds the owner's successor key too), and the hosted doors.
struct Hosted {
    sql: RusqliteDoSql,
    trust: String,
    deployment: String,
}

impl Hosted {
    fn new(host: &Host) -> Self {
        use ring::signature::KeyPair as _;
        let sql = RusqliteDoSql::with_store_schema();
        let public_bindings: Vec<Value> = [("owner", "owner", 1u8), ("worker", "worker", 2u8), ("owner", "successor", 3u8)]
            .into_iter()
            .map(|(principal, name, seed)| {
                let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
                    .expect("synthetic key");
                let public_key_hex: String = key
                    .public_key()
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                json!({"actor":{"principal":principal,"algorithm":"ed25519-custodian","key_id":format!("credential:norm/{name}#local")},"public_key_hex":public_key_hex})
            })
            .collect();
        let image = format!("sha256:{}", "c".repeat(64));
        let hosted = Self {
            sql,
            trust: json!({"bindings":[],"public_bindings":public_bindings,"creation_grants":[]})
                .to_string(),
            deployment: json!({
                "planning": host.planning.to_string(),
                "runtime": json!(host.runtime).to_string(),
                "deployed_image": image,
                "image_binding": json!({"protocol":"whipplescript.exec.runtime-image/v1","image_id":image,"runtime":host.runtime}).to_string(),
                "time_basis": "hosted-door-rows",
                "now": format!(
                    "unix:{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("clock")
                        .as_secs()
                ),
            })
            .to_string(),
        };
        hosted.vcs().init("t0").expect("hosted mainline");
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
            hosted.write(MAINLINE_BRANCH_ID, path, Some(&demo(path)), cut, "t1");
        }
        hosted.line("work", "t2");
        hosted
    }

    fn vcs(
        &self,
    ) -> whipplescript_store::vcs::WorkspaceVcs<
        whipplescript_host_do::do_branches::DoBranches<RusqliteDoSql>,
        whipplescript_host_do::do_branches::DoContentBlobs<RusqliteDoSql>,
    > {
        whipplescript_host_do::do_branches::compose_vcs_shared(&self.sql).expect("hosted workspace")
    }

    /// A stream `name` on its own line `line-<name>` off the mainline.
    fn line(&self, name: &str, at: &str) {
        let line = format!("line-{name}");
        self.vcs()
            .create_branch(&line, None, MAINLINE_BRANCH_ID, at)
            .expect("hosted line");
        whipplescript_host_do::do_workstreams::DoWorkstreams::new(self.sql.clone())
            .expect("hosted streams")
            .create_stream(name, None, &line, at, None)
            .expect("hosted stream");
    }

    fn write(&self, branch: &str, path: &str, body: Option<&str>, cut: &str, at: &str) {
        let written = self
            .vcs()
            .write(branch, path, body, cut, at)
            .expect("hosted write");
        assert!(
            matches!(
                written,
                whipplescript_store::vcs::VcsWriteOutcome::Written { .. }
            ),
            "{written:?}"
        );
    }

    fn read(&self, branch: &str, path: &str) -> Option<String> {
        self.vcs().read(branch, path).expect("hosted read")
    }

    fn head(&self, branch: &str) -> Option<String> {
        self.vcs()
            .get_branch(branch)
            .expect("hosted branch")
            .and_then(|row| row.head_cut_id)
    }

    /// Import `events` through the hosted command door, pinning `checkpoint`
    /// first if the object holds none. An import leases every line a
    /// charter it carries declares gated.
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
        self.leased(json!({"kind":"import","events":events}))
            .expect("the object admits the history")
    }

    /// One norm command through the hosted door, leasing the gated refs a
    /// charter-installing act declares, as the Worker's door does.
    fn leased(&self, command: Value) -> Result<Value, String> {
        let sql = self.sql.clone();
        let mut lease = |declared: &[String]| {
            whipplescript_store::branches::lease_gated_refs(
                &mut whipplescript_host_do::do_branches::DoBranches::new(sql.clone())?,
                declared,
                "hosted-door",
            )
        };
        execute_hosted_norm_command_with_artifacts(
            &mut DoSqliteStore::new(self.sql.clone()),
            &self.trust,
            &json!({"protocol":"whipplescript.norm.commands/v1","command":command}).to_string(),
            None,
            Some(&mut lease),
            None,
        )
        .map(|answer| {
            serde_json::from_str::<Value>(&answer).expect("command JSON")["result"].clone()
        })
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
        )
        .map(|answer| {
            serde_json::from_str::<Value>(&answer).expect("command JSON")["result"].clone()
        })
    }

    fn snapshot(&self) -> Value {
        self.command(json!({"kind": "snapshot"}))
            .expect("hosted snapshot")["snapshot"]
            .clone()
    }

    fn events(&self) -> usize {
        self.command(json!({"kind": "export"}))
            .expect("hosted export")["events"]
            .as_array()
            .expect("events")
            .len()
    }

    fn promote(&self, stream: &str, promotion: &str, tokens: &[&str]) -> Value {
        let answer = whipplescript_host_do::norm_commands::execute_installed_hosted_norm_promotion(
            &self.sql,
            &self.trust,
            &json!({"protocol":"whipplescript.norm.promotion/v1","command":{"stream":stream,"promotion":promotion,"tokens":tokens}}).to_string(),
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

    /// The deployment's gate configuration as the Worker installs it for the
    /// in-language doors: no clock of its own.
    fn norm_gate(&self) -> HostedNormGate {
        let mut deployment: Value = serde_json::from_str(&self.deployment).expect("deployment");
        let fields = deployment.as_object_mut().expect("deployment fields");
        fields.remove("time_basis");
        fields.remove("now");
        HostedNormGate {
            trust: self.trust.clone(),
            deployment: deployment.to_string(),
        }
    }

    /// A selective verb through the object's in-language door for the
    /// instance `instance`, with the deployment's gate or none.
    fn selective(
        &self,
        instance: &str,
        effect: &str,
        target: &str,
        input: Value,
        gated: bool,
    ) -> CapabilityOutcome {
        whipplescript_host_do::do_workstreams::DoVcsSelectiveCapabilityProvider {
            sql: self.sql.clone(),
            instance_id: instance.into(),
            norm_gate: gated.then(|| self.norm_gate()),
            now_unix_ms: 1_790_000_000_000,
        }
        .produce(
            &whipplescript_store::ClaimableEffect {
                attempt_admission_event_id: None,
                effect_id: effect.into(),
                kind: "capability.call".into(),
                target: Some(target.into()),
                profile: None,
                input_json: input.to_string(),
                required_capabilities_json: "[]".into(),
                declared_profiles_json: "[]".into(),
            },
            &whipplescript_kernel::effect_config::EffectConfig::default(),
        )
    }

    /// The mainline gate over this object's ledger, built from the
    /// deployment's planning inputs exactly as its doors build it, for a
    /// door this test drives itself.
    fn gate<T>(
        &self,
        door: AdmissionDoor,
        tokens: &[String],
        f: impl FnOnce(&mut dyn MainlineGate) -> T,
    ) -> T {
        let deployment: Value = serde_json::from_str(&self.deployment).expect("deployment");
        let text = |field: &str| deployment[field].as_str().expect(field).to_owned();
        let configuration = PlanningConfiguration::parse(&text("planning")).expect("planning");
        let policy =
            ProtectedPythonPolicy::new(&text("runtime"), &text("time_basis")).expect("policy");
        let pinned: PythonRuntime = serde_json::from_str(&text("runtime")).expect("runtime");
        let verify = move |selected: &PythonRuntime| {
            if *selected == pinned {
                Ok(())
            } else {
                Err("the deployment does not run the selected runtime".to_owned())
            }
        };
        let trust: Value = serde_json::from_str(&self.trust).expect("trust");
        let roots: Vec<NormPublicKeyVerifier> = trust["public_bindings"]
            .as_array()
            .expect("public bindings")
            .iter()
            .map(|binding| {
                NormPublicKeyVerifier::new(
                    serde_json::from_value::<NormPublicKeyBinding>(binding.clone())
                        .expect("binding"),
                )
                .expect("public key")
            })
            .collect();
        let verifier = NormGovernanceVerifier::new(
            roots
                .iter()
                .map(|root| NormPrincipalBinding {
                    actor: root.actor().clone(),
                    verifier: root,
                })
                .collect(),
            BTreeSet::new(),
        )
        .expect("hosted verifier");
        let ledger = DoSqliteStore::new(self.sql.clone());
        let runtime = DoSqliteStore::new(self.sql.clone());
        let now = text("now");
        let mut gate = NormMainlineAdmission::new(
            &ledger,
            Ok(AdmissionHost {
                now: Some(&now),
                verifier: &verifier,
                configuration: &configuration,
                runtime: &runtime,
                policy: &policy,
                verify_runtime: &verify,
            }),
            door,
            MAINLINE_BRANCH_ID,
        )
        .with_tokens(tokens.iter().cloned());
        f(&mut gate)
    }
}

/// The demo's A0: each file and the cut that writes it.
const A0: [(&str, &str); 3] = [
    ("src/parser.py", "a0-0"),
    ("src/auth.py", "a0-1"),
    ("checks/q0.json", "a0"),
];

/// A gate that runs `between` after its preparation and before its commit,
/// as a concurrent writer would, and remembers what it prepared.
struct Between<'g, F: FnMut()> {
    inner: &'g mut dyn MainlineGate,
    between: F,
    prepared: Vec<GateVerdict>,
    committed: Vec<GateCommit>,
}

impl<F: FnMut()> MainlineGate for Between<'_, F> {
    fn prepare(
        &mut self,
        base_cut: Option<&str>,
        proposed_cut: &str,
        artifacts: &whipplescript_store::norm_commands::NormArtifactCapture<'_>,
    ) -> StoreResult<GateVerdict> {
        let verdict = self.inner.prepare(base_cut, proposed_cut, artifacts)?;
        self.prepared.push(verdict.clone());
        Ok(verdict)
    }

    fn commit(&mut self, advance: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<GateCommit> {
        (self.between)();
        let committed = self.inner.commit(advance)?;
        self.committed.push(committed.clone());
        Ok(committed)
    }
}

/// The demo's workspace and ledger on both hosts: A0 on each mainline, W's
/// line `work` off it, C0 bootstrapped (with an issue vocabulary), and R0
/// accepted with Q0 as its support contract.
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
        let host = Host::install(&fixture, &charter);
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
        drop(vcs);
        let world_fixture = fixture;
        let world = Self {
            fixture: world_fixture,
            charter: charter.clone(),
            host,
            hosted,
            requirement: String::new(),
        };
        world.native_line("work", "t2");
        world.fixture.write("charter.json", &json!(charter));
        world.fixture.run(&[
            "bootstrap",
            "--as",
            "owner",
            "--creator",
            "worker",
            "--charter",
            "charter.json",
        ]);
        let requirement = world.create_requirement("custody-authorization", "owner");
        world.hosted.sync(&world);
        Self {
            requirement,
            ..world
        }
    }

    fn items(&self) -> PathBuf {
        self.fixture.root.join("items.sqlite")
    }

    fn vcs(&self) -> NativeWorkspaceVcs {
        NativeWorkspaceVcs::open(
            self.fixture.root.join("branches.sqlite"),
            self.fixture.root.join("content.sqlite"),
        )
        .expect("workspace")
    }

    /// A stream `name` on its own native line `line-<name>`.
    fn native_line(&self, name: &str, at: &str) {
        let line = format!("line-{name}");
        self.vcs()
            .create_branch(&line, None, MAINLINE_BRANCH_ID, at)
            .expect("line");
        WorkstreamStore::open(self.fixture.root.join("workstreams.sqlite"))
            .expect("streams")
            .create_stream(name, None, &line, at, None)
            .expect("stream");
    }

    /// A stream `name` on both hosts.
    fn stream(&self, name: &str, at: &str) {
        self.native_line(name, at);
        self.hosted.line(name, at);
    }

    /// Create and accept a requirement as `signer`, with Q0 as its contract.
    fn create_requirement(&self, name: &str, signer: &str) -> String {
        let file = format!("{name}.json");
        self.fixture
            .write(&file, &requirement_fields(name, &runtime()));
        let requirement =
            self.fixture
                .run(&["create", "requirement@1", "--as", signer, "--fields", &file])["result"]
                ["event_id"]
                .as_str()
                .expect("requirement")
                .to_owned();
        self.fixture
            .run(&["transition", &requirement, "accepted", "--as", signer]);
        requirement
    }

    /// Write (or, with `None`, delete) `path` on `branch` on both hosts.
    fn put(&self, branch: &str, path: &str, body: Option<&str>, cut: &str, at: &str) {
        self.vcs()
            .write(branch, path, body, cut, at)
            .expect("native write");
        self.hosted.write(branch, path, body, cut, at);
    }

    /// Write `path` on W's line on both hosts.
    fn line(&self, path: &str, body: &str, cut: &str, at: &str) {
        self.put("line-work", path, Some(body), cut, at);
    }

    fn read(&self, branch: &str, path: &str) -> Option<String> {
        self.vcs().read(branch, path).expect("read")
    }

    fn head(&self, branch: &str) -> Option<String> {
        self.vcs()
            .get_branch(branch)
            .expect("branch")
            .and_then(|row| row.head_cut_id)
    }

    /// Run Q0 on `cut`, settle the run on both hosts' journals, and publish
    /// what it observed natively. `wrong` names the cases that come out the
    /// opposite of what R0 expects.
    fn observe(&self, cut: &str, run: &str, wrong: &[&str]) -> String {
        let prepared: PreparedNormExecution = with_verifier(&self.fixture, |verifier| {
            let ledger = WorkItemStore::open(self.items()).expect("ledger");
            let view = ledger.norm_view(verifier).expect("view");
            let history = CapturedNormHistory::capture(
                &view,
                &ledger.export_events().expect("history"),
                verifier,
                NormHistoryLimits::default(),
            )
            .expect("history");
            let artifact = self
                .vcs()
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
        });
        let cases: Vec<(&str, &str, Value)> = self
            .host
            .required
            .iter()
            .map(|case| {
                let expected = case.expected.as_bool().expect("boolean case");
                let actual = expected != wrong.contains(&case.id.as_str());
                (case.id.as_str(), case.assertion.as_str(), json!(actual))
            })
            .collect();
        let failed = !wrong.is_empty();
        let receipt: HttpResponse = execution::receipt_cases(&prepared, &cases, failed);
        drop(execution::journal_execution_as(
            SqliteStore::open(self.fixture.root.join("runtime.sqlite")).expect("runtime"),
            &prepared,
            &receipt,
            failed,
            &format!("instance-{run}"),
            &format!("run-{run}"),
        ));
        drop(execution::journal_execution_as(
            DoSqliteStore::new(self.hosted.sql.clone()),
            &prepared,
            &receipt,
            failed,
            &format!("instance-{run}"),
            &format!("run-{run}"),
        ));
        let published = whip_in(
            &self.fixture,
            &self.items(),
            &[
                "--json",
                "norm",
                "publish-observation",
                &format!("instance-{run}"),
                &format!("run-{run}"),
                "local-observation@1",
                "--as",
                "owner",
            ],
            None,
        );
        assert!(published.status.success(), "{}", stderr(&published));
        let published: Value = serde_json::from_slice(&published.stdout).expect("publication");
        published
            .get("event_id")
            .or_else(|| published["result"].get("event_id"))
            .and_then(Value::as_str)
            .expect("the published observation")
            .to_owned()
    }

    /// `norm impact` natively.
    fn planned_native(&self, before: &str, after: &str) -> Value {
        let output = whip_in(
            &self.fixture,
            &self.items(),
            &["--json", "norm", "impact", before, after],
            self.host.configured(),
        );
        assert!(output.status.success(), "{}", stderr(&output));
        let planned: Value = serde_json::from_slice(&output.stdout).expect("impact JSON");
        if planned.get("plan").is_some() {
            planned
        } else {
            planned["result"].clone()
        }
    }

    /// The impact answer from each host: native, then the synced object.
    fn planned(&self, before: &str, after: &str) -> [Value; 2] {
        self.hosted.sync(self);
        [
            self.planned_native(before, after),
            self.hosted.planned(before, after),
        ]
    }

    /// Promote `stream` onto Main on both hosts; each refuses, and neither
    /// mainline moves. Returns each refusal's detail.
    fn refused(&self, stream: &str, promotion: &str, tokens: &[&str]) -> [Value; 2] {
        self.hosted.sync(self);
        let (native_main, hosted_main) = (
            self.head(MAINLINE_BRANCH_ID),
            self.hosted.head(MAINLINE_BRANCH_ID),
        );
        let mut args = vec!["stream", "promote", stream];
        for token in tokens {
            args.extend(["--token", token]);
        }
        let native = whip_in(&self.fixture, &self.items(), &args, self.host.configured());
        assert!(
            !native.status.success(),
            "the mainline moved: {}",
            stdout(&native)
        );
        let native: Value = serde_json::from_slice(&native.stdout).expect("refusal JSON");
        let hosted = self.hosted.promote(stream, promotion, tokens);
        assert!(hosted.get("promoted").is_none(), "{hosted}");
        assert_eq!(native["reason"], hosted["reason"], "{native} {hosted}");
        assert_eq!(self.head(MAINLINE_BRANCH_ID), native_main);
        assert_eq!(self.hosted.head(MAINLINE_BRANCH_ID), hosted_main);
        [native["detail"].clone(), hosted["detail"].clone()]
    }

    /// Promote `stream` onto Main on both hosts; both admit it.
    fn admitted(&self, stream: &str, promotion: &str, tokens: &[&str]) {
        self.hosted.sync(self);
        let mut args = vec!["stream", "promote", stream];
        for token in tokens {
            args.extend(["--token", token]);
        }
        let native = whip_in(&self.fixture, &self.items(), &args, self.host.configured());
        assert!(native.status.success(), "{}", stdout(&native));
        let hosted = self.hosted.promote(stream, promotion, tokens);
        assert_eq!(hosted["promoted"], stream, "{hosted}");
    }

    /// The snapshot from each host.
    fn snapshots(&self) -> [Value; 2] {
        self.hosted.sync(self);
        [
            self.fixture.run(&["snapshot"])["result"]["snapshot"].clone(),
            self.hosted.snapshot(),
        ]
    }

    fn events(&self) -> usize {
        self.fixture.run(&["export"])["result"]["events"]
            .as_array()
            .expect("events")
            .len()
    }

    /// The history of the ledger at `items`, and its pinned checkpoint.
    fn history(&self, items: &Path) -> (NormCheckpoint, Vec<TrackerEvent>) {
        with_view(&self.fixture, items, |ledger, _| {
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

    /// Import `events` into the native ledger at `items`.
    fn import(&self, items: &Path, events: &[TrackerEvent]) -> usize {
        with_verifier(&self.fixture, |verifier| {
            WorkItemStore::open(items)
                .expect("replica")
                .import_norm_events(events, verifier)
                .expect("the replica admits the history")
        })
    }

    /// A statement about the current native ledger, signed by `signer`.
    fn signed(
        &self,
        signer: &str,
        nonce: &str,
        action: NormAct,
        premises: Option<NormPremises>,
    ) -> Value {
        let statement = NormStatement {
            protocol: "whipplescript.norm/v1".into(),
            actor: actor(signer),
            nonce: nonce.into(),
            created_at: "2026-09-28T00:00:00Z".into(),
            action,
            premises,
        };
        self.fixture.write("statement.json", &json!(statement));
        self.fixture
            .run(&["sign", "--as", signer, "--statement", "statement.json"])
    }

    /// An activation of `charter` retaining every vocabulary in force, as
    /// its signed act and as the proposal file `name` the CLI takes.
    fn activation(&self, name: &str, charter: &NormCharter, signer: &str) -> Value {
        let (ledger, previous, frontier, in_force) =
            with_view(&self.fixture, &self.items(), |_, view| {
                (
                    view.ledger.clone(),
                    view.authority_head.clone(),
                    view.frontier.iter().cloned().collect::<Vec<_>>(),
                    view.charter.clone(),
                )
            });
        let migration: Vec<Value> = in_force
            .vocabularies
            .iter()
            .map(|entry| {
                json!({
                    "from": Vocabulary::new(entry.definition.clone()).expect("definition").reference(),
                    "plan": {"plan": "retain"},
                })
            })
            .collect();
        self.fixture
            .write(name, &json!({"charter": charter, "migration": migration}));
        self.signed(
            signer,
            &format!("activate-{name}"),
            NormAct::Activate {
                ledger,
                previous,
                charter: charter.clone(),
                migration: serde_json::from_value(json!(migration)).expect("migration"),
                changes: Vec::new(),
                frontier,
            },
            None,
        )
    }

    /// The native mainline gate over this world's ledger and runtime, as
    /// `with_mainline_admission` builds it, for a door this test drives.
    fn gate<T>(
        &self,
        door: AdmissionDoor,
        tokens: &[String],
        f: impl FnOnce(&mut dyn MainlineGate) -> T,
    ) -> T {
        with_verifier(&self.fixture, |verifier| {
            let ledger = WorkItemStore::open(self.items()).expect("ledger");
            let configuration =
                PlanningConfiguration::parse(&self.host.planning.to_string()).expect("planning");
            let runtime =
                SqliteStore::open(self.fixture.root.join("runtime.sqlite")).expect("runtime");
            let policy = ProtectedPythonPolicy::new(
                &json!(self.host.runtime).to_string(),
                "native-door-rows",
            )
            .expect("policy");
            let pinned = self.host.runtime.clone();
            let verify = move |selected: &PythonRuntime| {
                if *selected == pinned {
                    Ok(())
                } else {
                    Err("the host does not run the selected runtime".to_owned())
                }
            };
            let mut gate = NormMainlineAdmission::new(
                &ledger,
                Ok(AdmissionHost {
                    now: None,
                    verifier,
                    configuration: &configuration,
                    runtime: &runtime,
                    policy: &policy,
                    verify_runtime: &verify,
                }),
                door,
                MAINLINE_BRANCH_ID,
            )
            .with_tokens(tokens.iter().cloned());
            f(&mut gate)
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

impl Hosted {
    /// Bring the object's ledger up to the world's native one.
    fn sync(&self, world: &World) -> Value {
        let (checkpoint, events) = world.history(&world.items());
        self.import(&checkpoint, &events)
    }
}

/// A requirement's impact entries in a plan.
fn impacts<'a>(planned: &'a Value, requirement: &str) -> &'a Vec<Value> {
    planned["plan"]["requirements"][requirement]
        .as_array()
        .unwrap_or_else(|| panic!("{requirement} has no impact in {planned}"))
}

/// The work kinds a requirement's support needs in a plan.
fn work(planned: &Value, requirement: &str) -> Vec<String> {
    impacts(planned, requirement)
        .iter()
        .map(|impact| {
            impact["work"]["kind"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
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

/// The event id a norm command answered with.
fn event_id(answer: &Value) -> String {
    answer["result"]["event_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no event in {answer}"))
        .to_owned()
}

/// NP-07: the candidate changes only `src/parser.py`, to the negative
/// mutation. On both hosts the subject's bytes are identical on the line,
/// yet A0's support no longer carries: Q0 is scheduled, fails at
/// worker-deny, and gated admission refuses for repair.
#[test]
fn np07_a_parser_mutation_invalidates_support_while_the_subject_is_byte_identical() {
    let world = World::new();
    let a0 = world.observe("a0", "a0", &[]);
    for planned in world.planned("a0", "a0") {
        assert_eq!(work(&planned, &world.requirement), ["supported"]);
    }
    world.line("src/parser.py", MUTATED, "a1", "t3");
    // The subject, read back from each host's own line: the same bytes.
    assert_eq!(
        world.read("line-work", "src/auth.py"),
        Some(demo("src/auth.py"))
    );
    assert_eq!(
        world.hosted.read("line-work", "src/auth.py"),
        Some(demo("src/auth.py"))
    );
    assert_eq!(
        world.hosted.read("line-work", "src/parser.py").as_deref(),
        Some(MUTATED)
    );
    let scheduled = world.planned("a0", "a1");
    for planned in &scheduled {
        let impact = &impacts(planned, &world.requirement)[0];
        assert_eq!(impact["work"]["kind"], "check", "{impact}");
        let selection = &impact["selection"];
        assert_eq!(selection["conformance"], "stale");
        assert!(ids(&selection["positive"]).is_empty());
        assert_eq!(ids(&selection["stale"]), set([a0.as_str()]));
    }
    assert_eq!(
        impacts(&scheduled[0], &world.requirement)[0]["work"],
        impacts(&scheduled[1], &world.requirement)[0]["work"],
        "both hosts schedule the same check"
    );
    let failing = world.observe("a1", "a1", &["worker-deny"]);
    for planned in world.planned("a0", "a1") {
        let impact = &impacts(&planned, &world.requirement)[0];
        assert_eq!(impact["work"]["kind"], "repair", "{impact}");
        assert_eq!(impact["selection"]["conformance"], "violated");
        assert_eq!(
            ids(&impact["selection"]["counterevidence"]),
            set([failing.as_str()])
        );
    }
    for detail in world.refused("work", "mutated", &[]) {
        assert_eq!(
            detail["requirements"][&world.requirement],
            json!(["repair"]),
            "{detail}"
        );
    }
}

/// NP-10: a new applicable requirement arrives with no evidence. Both hosts'
/// inventories keep the duty, both plans ask for its check, and both gates
/// refuse naming it, though R0 is supported: never an empty satisfied gate.
#[test]
fn np10_a_new_requirement_without_evidence_keeps_its_duty_and_refuses_on_both_hosts() {
    let world = World::new();
    world.line("src/parser.py", REPAIRED, "a1", "t3");
    world.observe("a1", "a1", &[]);
    for planned in world.planned("a0", "a1") {
        assert_eq!(work(&planned, &world.requirement), ["supported"]);
    }
    let r1 = world.create_requirement("custody-audit", "owner");
    let planned = world.planned("a0", "a1");
    for planned in &planned {
        assert_eq!(work(planned, &world.requirement), ["supported"]);
        let impact = &impacts(planned, &r1)[0];
        assert_eq!(impact["work"]["kind"], "check", "{impact}");
        assert!(ids(&impact["selection"]["positive"]).is_empty());
    }
    let native = world.fixture.run(&["inventory"])["result"]["inventory"].clone();
    let hosted = world
        .hosted
        .command(json!({"kind": "inventory"}))
        .expect("hosted inventory")["inventory"]
        .clone();
    assert_eq!(native, hosted, "both hosts keep the same inventory");
    assert!(native["requirements"].get(&r1).is_some(), "{native}");
    for detail in world.refused("work", "new-requirement", &[]) {
        let requirements = detail["requirements"].as_object().expect("requirements");
        assert_eq!(
            requirements.keys().collect::<Vec<_>>(),
            [&r1],
            "only the new duty lacks support: {detail}"
        );
        assert_eq!(detail["requirements"][&r1], json!(["check"]), "{detail}");
    }
}

/// NP-10: a relevant resource is deleted on the candidate — first R0's
/// dependency, then its subject. Neither host treats the deletion as
/// satisfying R0: its plan keeps a duty, its inventory keeps R0, and its
/// gate refuses naming R0.
#[test]
fn np10_deleting_a_relevant_resource_never_yields_an_empty_satisfied_gate() {
    let world = World::new();
    world.observe("a0", "a0", &[]);
    // The dependency's deletion asks for a fresh check; the subject's
    // leaves a resource gap.
    for (path, cut, at, needs) in [
        ("src/parser.py", "a1", "t3", "check"),
        ("src/auth.py", "a2", "t4", "resource_gap"),
    ] {
        world.put("line-work", path, None, cut, at);
        assert_eq!(world.read("line-work", path), None);
        assert_eq!(world.hosted.read("line-work", path), None);
        let planned = world.planned("a0", cut);
        for plan in &planned {
            let kinds = work(plan, &world.requirement);
            assert!(!kinds.is_empty(), "{plan}");
            assert!(
                kinds.iter().all(|kind| kind != "supported"),
                "deleting {path} left R0 supported: {plan}"
            );
        }
        assert_eq!(work(&planned[0], &world.requirement), [needs]);
        assert_eq!(work(&planned[1], &world.requirement), [needs]);
        let native = world.fixture.run(&["inventory"])["result"]["inventory"].clone();
        let hosted = world
            .hosted
            .command(json!({"kind": "inventory"}))
            .expect("hosted inventory")["inventory"]
            .clone();
        assert_eq!(native, hosted);
        assert!(
            native["requirements"].get(&world.requirement).is_some(),
            "{native}"
        );
        for detail in world.refused("work", &format!("deleted-{cut}"), &[]) {
            assert_eq!(
                detail["requirements"][&world.requirement],
                json!([needs]),
                "deleting {path} is refused naming R0: {detail}"
            );
        }
    }
}

/// Restore Main to `to` through a door this test drives on the native host,
/// running `between` after the gate prepared and before it commits.
fn native_restore(
    world: &World,
    to: &str,
    cut: &str,
    tokens: &[String],
    between: impl FnMut(),
) -> (
    StoreResult<RestoreOutcome>,
    Vec<GateVerdict>,
    Vec<GateCommit>,
) {
    world.gate(AdmissionDoor::Restore, tokens, |gate| {
        let mut gate = Between {
            inner: gate,
            between,
            prepared: Vec::new(),
            committed: Vec::new(),
        };
        let outcome = world
            .vcs()
            .restore(MAINLINE_BRANCH_ID, to, cut, "t9", &mut gate);
        (outcome, gate.prepared, gate.committed)
    })
}

/// The same on the hosted object.
fn hosted_restore(
    world: &World,
    to: &str,
    cut: &str,
    tokens: &[String],
    between: impl FnMut(),
) -> (
    StoreResult<RestoreOutcome>,
    Vec<GateVerdict>,
    Vec<GateCommit>,
) {
    world.hosted.gate(AdmissionDoor::Restore, tokens, |gate| {
        let mut gate = Between {
            inner: gate,
            between,
            prepared: Vec::new(),
            committed: Vec::new(),
        };
        let outcome = world
            .hosted
            .vcs()
            .restore(MAINLINE_BRANCH_ID, to, cut, "t9", &mut gate);
        (outcome, gate.prepared, gate.committed)
    })
}

/// NP-14 on both hosts: a door prepared admission, a premise changed before
/// it committed, and it moved nothing — no head, no op, no receipt.
fn assert_stale(
    world: &World,
    host: &str,
    cut: &str,
    answer: (
        StoreResult<RestoreOutcome>,
        Vec<GateVerdict>,
        Vec<GateCommit>,
    ),
) {
    let (outcome, prepared, committed) = answer;
    assert_eq!(prepared, [GateVerdict::Admit], "{host} {cut}: {outcome:?}");
    assert_eq!(
        committed,
        [GateCommit::Stale {
            changed: STALE.into()
        }],
        "{host} {cut}"
    );
    assert!(
        matches!(&outcome, Ok(RestoreOutcome::GateStale { changed }) if changed == STALE),
        "{host} {cut}: {outcome:?}"
    );
    let (head, op, ops) = if host == "native" {
        let vcs = world.vcs();
        (
            world.head(MAINLINE_BRANCH_ID),
            vcs.get_op(&format!("op-{cut}")).expect("op"),
            vcs.list_ops(1000).expect("ops"),
        )
    } else {
        let vcs = world.hosted.vcs();
        (
            world.hosted.head(MAINLINE_BRANCH_ID),
            vcs.get_op(&format!("op-{cut}")).expect("op"),
            vcs.list_ops(1000).expect("ops"),
        )
    };
    assert_eq!(head.as_deref(), Some("a0"), "{host}: the mainline moved");
    assert!(op.is_none(), "{host}: a stale door logged its success");
    assert!(
        ops.iter()
            .all(|op| op.kind != "restore" && op.op_id != format!("op-{cut}")),
        "{host}: the op log records a restore: {ops:?}"
    );
}

/// NP-14: each premise a certificate rests on changes between a door's
/// preparation and its commit — a new evidence-frontier event, the
/// requester's token, the charter (an activation), the authority (a
/// rotation), and a new requirement — and on both hosts every certificate
/// goes stale: the ref does not move and the op journal records no success.
/// Re-prepared after the last change, the door refuses naming the new
/// requirement.
#[test]
fn np14_every_changed_premise_leaves_a_prepared_door_stale_on_both_hosts() {
    let world = World::new();
    world.stream("release", "t2");
    world.line("src/parser.py", REPAIRED, "a1", "t3");
    world.observe("a1", "a1", &[]);
    world.hosted.sync(&world);
    for planned in world.planned("a0", "a1") {
        assert_eq!(work(&planned, &world.requirement), ["supported"]);
    }
    let (ops_native, ops_hosted) = (
        world.vcs().list_ops(1000).expect("ops").len(),
        world.hosted.vcs().list_ops(1000).expect("ops").len(),
    );
    let restore = |host: &str, premise: &str, tokens: &[String], between: &mut dyn FnMut()| {
        let cut = format!("{premise}-{host}");
        let answer = if host == "native" {
            native_restore(&world, "a1", &cut, tokens, between)
        } else {
            hosted_restore(&world, "a1", &cut, tokens, between)
        };
        assert_stale(&world, host, &cut, answer);
    };

    // A new evidence-frontier event: another run of Q0 published.
    restore("native", "evidence", &[], &mut || {
        world.observe("a1", "a1-again", &[]);
    });
    restore("hosted", "evidence", &[], &mut || {
        world.hosted.sync(&world);
    });

    // The requester's token: W's grant over `src/**`, whose record the owner
    // expires after the door certified T1.
    world.fixture.write(
        "claim.json",
        &json!({"purpose": "repair the parser", "selectors": ["src/**"], "mode": "exclusive"}),
    );
    let claim = event_id(&world.fixture.run(&[
        "create",
        "reservation@1",
        "--as",
        "worker",
        "--fields",
        "claim.json",
    ]));
    let t1 = event_id(
        &world
            .fixture
            .run(&["transition", &claim, "granted", "--as", "owner"]),
    );
    world.hosted.sync(&world);
    // Without it, both hosts refuse at preparation; with it, both admit.
    for (host, (outcome, prepared, _)) in [
        (
            "native",
            native_restore(&world, "a1", "untokened-native", &[], || {}),
        ),
        (
            "hosted",
            hosted_restore(&world, "a1", "untokened-hosted", &[], || {}),
        ),
    ] {
        assert!(
            matches!(&outcome, Ok(RestoreOutcome::GateRefused(refusal)) if refusal.detail["reservations"].get(&claim).is_some()),
            "{host}: {outcome:?}"
        );
        assert!(matches!(prepared[..], [GateVerdict::Refuse(_)]), "{host}");
    }
    let tokens = [t1.clone()];
    restore("native", "token", &tokens, &mut || {
        world
            .fixture
            .run(&["transition", &claim, "expired", "--as", "owner"]);
    });
    restore("hosted", "token", &tokens, &mut || {
        world.hosted.sync(&world);
    });

    // The charter: the owner activates C1, which also gates `release`.
    let mut c1 = world.charter.clone();
    c1.gated_refs = vec!["line-release".into()];
    world.activation("c1.json", &c1, "owner");
    restore("native", "charter", &[], &mut || {
        world
            .fixture
            .run(&["activate", "--as", "owner", "--proposal", "c1.json"]);
    });
    restore("hosted", "charter", &[], &mut || {
        world.hosted.sync(&world);
    });

    // The authority: the owner rotates to the successor key.
    restore("native", "authority", &[], &mut || {
        world
            .fixture
            .run(&["rotate", "--as", "owner", "--successor", "successor"]);
    });
    restore("hosted", "authority", &[], &mut || {
        world.hosted.sync(&world);
    });
    let [native, hosted] = world.snapshots();
    assert_eq!(native["checkpoint"], hosted["checkpoint"]);
    assert_eq!(native["charter"], json!(c1));
    assert_eq!(hosted["charter"], json!(c1));

    // A requirement: R1 accepted, under the successor's authority, with no
    // evidence. Prepared again, each door refuses naming it.
    let mut r1 = None;
    restore("native", "requirement", &[], &mut || {
        r1 = Some(world.create_requirement("custody-audit", "successor"));
    });
    restore("hosted", "requirement", &[], &mut || {
        world.hosted.sync(&world);
    });
    let r1 = r1.expect("R1");
    for (host, (outcome, _, committed)) in [
        (
            "native",
            native_restore(&world, "a1", "again-native", &[], || {}),
        ),
        (
            "hosted",
            hosted_restore(&world, "a1", "again-hosted", &[], || {}),
        ),
    ] {
        assert!(
            matches!(&outcome, Ok(RestoreOutcome::GateRefused(refusal)) if refusal.reason.contains(&r1)),
            "{host}: {outcome:?}"
        );
        assert!(committed.is_empty(), "{host}: a refusal never commits");
    }
    assert_eq!(world.head(MAINLINE_BRANCH_ID).as_deref(), Some("a0"));
    assert_eq!(world.hosted.head(MAINLINE_BRANCH_ID).as_deref(), Some("a0"));
    assert_eq!(world.vcs().list_ops(1000).expect("ops").len(), ops_native);
    assert_eq!(
        world.hosted.vcs().list_ops(1000).expect("ops").len(),
        ops_hosted
    );
}

/// NP-14's candidate premise: the certificate names the exact proposed cut,
/// so what a door proposes can change only by the ground it lands on moving
/// — another admitted door advancing Main after this one prepared. On both
/// hosts the prepared door then moves nothing and logs nothing: the
/// mainline is where the other door left it.
#[test]
fn np14_a_candidate_whose_base_moved_after_preparation_lands_nowhere_on_both_hosts() {
    let world = World::new();
    world.line("src/parser.py", REPAIRED, "a1", "t3");
    world.observe("a1", "a1", &[]);
    world.hosted.sync(&world);
    // A cut id already naming another result cannot carry the candidate.
    for (host, outcome) in [
        ("native", native_restore(&world, "a1", "a0-1", &[], || {}).0),
        ("hosted", hosted_restore(&world, "a1", "a0-1", &[], || {}).0),
    ] {
        assert!(
            matches!(&outcome, Err(whipplescript_store::StoreError::Conflict(reason)) if reason.contains("already names a different result")),
            "{host}: {outcome:?}"
        );
    }
    let (outcome, prepared, committed) = native_restore(&world, "a1", "outer-native", &[], || {
        let (other, _, _) = native_restore(&world, "a1", "other-native", &[], || {});
        assert!(
            matches!(other, Ok(RestoreOutcome::Restored { .. })),
            "{other:?}"
        );
    });
    let (hosted_outcome, hosted_prepared, hosted_committed) =
        hosted_restore(&world, "a1", "outer-hosted", &[], || {
            let (other, _, _) = hosted_restore(&world, "a1", "other-hosted", &[], || {});
            assert!(
                matches!(other, Ok(RestoreOutcome::Restored { .. })),
                "{other:?}"
            );
        });
    for (host, outcome, prepared, committed, head, op) in [
        (
            "native",
            outcome,
            prepared,
            committed,
            world.head(MAINLINE_BRANCH_ID),
            world.vcs().get_op("op-outer-native").expect("op"),
        ),
        (
            "hosted",
            hosted_outcome,
            hosted_prepared,
            hosted_committed,
            world.hosted.head(MAINLINE_BRANCH_ID),
            world.hosted.vcs().get_op("op-outer-hosted").expect("op"),
        ),
    ] {
        assert_eq!(prepared, [GateVerdict::Admit], "{host}");
        assert_eq!(committed, [GateCommit::Committed], "{host}");
        assert!(
            matches!(&outcome, Err(whipplescript_store::StoreError::Conflict(reason)) if reason.contains("head moved")),
            "{host}: {outcome:?}"
        );
        assert_eq!(
            head,
            Some(format!("other-{host}")),
            "{host}: the mainline is where the other door left it"
        );
        assert!(op.is_none(), "{host}: the stale door logged its success");
    }
}

/// NP-16: branch-bound undo and a transport onto ungated `scratch` never ask
/// the gate — neither host is even configured to evaluate it — while they
/// keep their own preconditions: a conflicting transport, a target that is
/// no line, and (hosted) an instance with no bound line are refused as
/// before. A release line the charter declares gated uses mainline's
/// predicate at both hosts' doors.
#[test]
fn np16_ungated_doors_skip_the_gate_and_keep_their_own_preconditions() {
    let world = World::new();
    world.stream("scratch", "t2");
    world.stream("release", "t2");
    world.line("src/parser.py", MUTATED, "a1", "t3");
    world.observe("a1", "a1", &["worker-deny"]);
    world.hosted.sync(&world);
    world
        .hosted
        .vcs()
        .bind_instance("inst-work", "line-work", "t3")
        .expect("hosted binding");

    // Native: no planning configured, so a gate consulted would refuse the
    // governed workspace as unevaluable. The scratch transport and the
    // branch-bound undo both apply.
    let transported = whip_in(
        &world.fixture,
        &world.items(),
        &[
            "--json",
            "branch",
            "transport",
            "line-work",
            "path(src/parser.py)",
            "--onto",
            "line-scratch",
            "--apply",
        ],
        None,
    );
    assert!(transported.status.success(), "{}", stderr(&transported));
    assert_eq!(
        world.read("line-scratch", "src/parser.py").as_deref(),
        Some(MUTATED)
    );
    // Hosted: the in-language door with no deployment gate.
    let applied = |outcome: CapabilityOutcome| match outcome {
        CapabilityOutcome::Produced(value) => value,
        CapabilityOutcome::Failed {
            error_kind,
            message,
        } => {
            panic!("refused ({error_kind}): {message}")
        }
    };
    let moved = applied(world.hosted.selective(
        "inst-work",
        "scratch-1",
        "vcs.transport",
        json!({"selection": "path(src/parser.py)", "onto": "scratch"}),
        false,
    ));
    assert_eq!(moved["variant"], "Applied", "{moved}");
    assert_eq!(
        world
            .hosted
            .read("line-scratch", "src/parser.py")
            .as_deref(),
        Some(MUTATED)
    );

    // The same selection onto the mainline asks the gate on both hosts.
    let onto_main = whip_in(
        &world.fixture,
        &world.items(),
        &[
            "--json",
            "branch",
            "transport",
            "line-work",
            "path(src/parser.py)",
            "--onto",
            "main",
            "--apply",
        ],
        world.host.configured(),
    );
    assert!(!onto_main.status.success(), "{}", stdout(&onto_main));
    let onto_main: Value = serde_json::from_slice(&onto_main.stdout).expect("refusal JSON");
    let hosted_main = gate_refused(world.hosted.selective(
        "inst-work",
        "main-1",
        "vcs.transport",
        json!({"selection": "path(src/parser.py)", "onto": "mainline"}),
        true,
    ));
    assert_eq!(onto_main["reason"], hosted_main);
    assert_eq!(
        onto_main["detail"]["requirements"][&world.requirement],
        json!(["repair"])
    );

    // Their own preconditions still hold: a target that is no line, and a
    // transport that conflicts with what the target already changed.
    let nowhere = whip_in(
        &world.fixture,
        &world.items(),
        &[
            "--json",
            "branch",
            "transport",
            "line-work",
            "path(src/parser.py)",
            "--onto",
            "line-nowhere",
            "--apply",
        ],
        None,
    );
    assert!(!nowhere.status.success(), "{}", stdout(&nowhere));
    assert_eq!(stderr(&nowhere).trim(), "transport refused: TargetMissing");
    match world.hosted.selective(
        "inst-work",
        "nowhere-1",
        "vcs.transport",
        json!({"selection": "path(src/parser.py)", "onto": "nowhere"}),
        false,
    ) {
        CapabilityOutcome::Failed { message, .. } => {
            assert_eq!(message, "`onto nowhere` names no stream")
        }
        CapabilityOutcome::Produced(value) => panic!("moved onto nothing: {value}"),
    }
    match world.hosted.selective(
        "inst-unbound",
        "unbound-1",
        "vcs.undo",
        json!({"selection": "path(src/parser.py)"}),
        false,
    ) {
        CapabilityOutcome::Failed { message, .. } => {
            assert!(message.contains("has no bound line"), "{message}")
        }
        CapabilityOutcome::Produced(value) => panic!("an unbound instance undid: {value}"),
    }
    world.put(
        "line-scratch",
        "src/parser.py",
        Some("# scratch\n"),
        "s1",
        "t4",
    );
    world.line("src/parser.py", REPAIRED, "a2", "t4");
    let conflicted = whip_in(
        &world.fixture,
        &world.items(),
        &[
            "--json",
            "branch",
            "transport",
            "line-work",
            "path(src/parser.py)",
            "--onto",
            "line-scratch",
            "--apply",
        ],
        None,
    );
    assert!(!conflicted.status.success(), "{}", stdout(&conflicted));
    assert!(
        stderr(&conflicted).contains("conflicted"),
        "{}",
        stderr(&conflicted)
    );
    let hosted_conflict = applied(world.hosted.selective(
        "inst-work",
        "scratch-2",
        "vcs.transport",
        json!({"selection": "path(src/parser.py)", "onto": "scratch"}),
        false,
    ));
    assert_eq!(
        hosted_conflict["variant"], "Conflicted",
        "{hosted_conflict}"
    );
    assert_eq!(
        world.read("line-scratch", "src/parser.py").as_deref(),
        Some("# scratch\n")
    );
    assert_eq!(
        world
            .hosted
            .read("line-scratch", "src/parser.py")
            .as_deref(),
        Some("# scratch\n")
    );

    // Branch-bound undo of the line's own parser edits, ungated on both.
    let undone = whip_in(
        &world.fixture,
        &world.items(),
        &[
            "--json",
            "branch",
            "undo",
            "line-work",
            "path(src/parser.py)",
            "--apply",
        ],
        None,
    );
    assert!(undone.status.success(), "{}", stderr(&undone));
    let hosted_undone = applied(world.hosted.selective(
        "inst-work",
        "undo-1",
        "vcs.undo",
        json!({"selection": "path(src/parser.py)"}),
        false,
    ));
    assert_eq!(hosted_undone["variant"], "Applied", "{hosted_undone}");
    assert_eq!(
        world.read("line-work", "src/parser.py"),
        world.hosted.read("line-work", "src/parser.py")
    );
    assert_eq!(
        world.read("line-work", "src/parser.py"),
        Some(demo("src/parser.py"))
    );

    // C1 declares `release` gated; both hosts lease its line.
    let mut c1 = world.charter.clone();
    c1.gated_refs = vec!["line-release".into()];
    world.activation("c1.json", &c1, "owner");
    world
        .fixture
        .run(&["activate", "--as", "owner", "--proposal", "c1.json"]);
    world.hosted.sync(&world);
    world.line("src/parser.py", MUTATED, "a3", "t5");
    world.hosted.sync(&world);
    let release = whip_in(
        &world.fixture,
        &world.items(),
        &[
            "--json",
            "branch",
            "transport",
            "line-work",
            "path(src/parser.py)",
            "--onto",
            "line-release",
            "--apply",
        ],
        world.host.configured(),
    );
    assert!(!release.status.success(), "{}", stdout(&release));
    let release: Value = serde_json::from_slice(&release.stdout).expect("refusal JSON");
    let hosted_release = gate_refused(world.hosted.selective(
        "inst-work",
        "release-1",
        "vcs.transport",
        json!({"selection": "path(src/parser.py)", "onto": "release"}),
        true,
    ));
    assert!(
        release["detail"]["requirements"]
            .get(&world.requirement)
            .is_some(),
        "{release}"
    );
    assert_eq!(release["reason"], hosted_release);
    // Unconfigured, the hosted door refuses it unevaluated: it is gated.
    assert!(gate_refused(world.hosted.selective(
        "inst-work",
        "release-2",
        "vcs.transport",
        json!({"selection": "path(src/parser.py)", "onto": "release"}),
        false,
    ))
    .contains("cannot be evaluated"));
    assert_eq!(
        world.read("line-release", "src/parser.py"),
        Some(demo("src/parser.py"))
    );
    assert_eq!(
        world.hosted.read("line-release", "src/parser.py"),
        Some(demo("src/parser.py"))
    );
}

/// A hosted in-language door's gate refusal, by its reason.
fn gate_refused(outcome: CapabilityOutcome) -> String {
    match outcome {
        CapabilityOutcome::Failed {
            error_kind,
            message,
        } if error_kind == "norm_gate_refused" => message,
        CapabilityOutcome::Failed { message, .. } => panic!("refused otherwise: {message}"),
        CapabilityOutcome::Produced(value) => panic!("the gated ref moved: {value}"),
    }
}

/// The native store's lease on a branch, if any.
fn native_lease(world: &World, branch: &str) -> Option<String> {
    use whipplescript_store::branches::Branches as _;
    whipplescript_store::branches::BranchStore::open(world.fixture.root.join("branches.sqlite"))
        .expect("branch store")
        .head_reservation(branch)
        .expect("reservation")
}

fn hosted_lease(world: &World, branch: &str) -> Option<String> {
    use whipplescript_store::branches::Branches as _;
    whipplescript_host_do::do_branches::DoBranches::new(world.hosted.sql.clone())
        .expect("hosted branches")
        .head_reservation(branch)
        .expect("hosted reservation")
}

/// NP-17: activating a charter that gates a line with a live instance
/// binding is refused through each host's norm command door, and nothing is
/// appended or leased. A successor charter that releases a gated line, or
/// that names the mainline among its gated lines, is refused on both hosts;
/// and no instance binds to a line once it is gated.
#[test]
fn np17_no_activation_gates_a_bound_line_or_releases_a_gate_on_either_host() {
    let world = World::new();
    world.stream("bound", "t2");
    world.stream("release", "t2");
    let bound = world
        .vcs()
        .bind_instance("inst-bound", "line-bound", "t3")
        .expect("bind");
    let hosted_bound = world
        .hosted
        .vcs()
        .bind_instance("inst-bound", "line-bound", "t3")
        .expect("hosted bind");
    assert!(!matches!(bound, BindOutcome::GatedRef), "{bound:?}");
    assert!(
        !matches!(hosted_bound, BindOutcome::GatedRef),
        "{hosted_bound:?}"
    );
    let (native_events, hosted_events) = (world.events(), world.hosted.events());
    let [native_before, hosted_before] = world.snapshots();

    // C1 gates the bound line.
    let mut gates_bound = world.charter.clone();
    gates_bound.gated_refs = vec!["line-bound".into()];
    let signed = world.activation("gates-bound.json", &gates_bound, "owner");
    let refused = world.fixture.refuse(&[
        "activate",
        "--as",
        "owner",
        "--proposal",
        "gates-bound.json",
    ]);
    assert!(
        stderr(&refused).contains("has live instance bindings (inst-bound)"),
        "{}",
        stderr(&refused)
    );
    let hosted_refused = world
        .hosted
        .leased(json!({"kind": "append", "event": signed}))
        .expect_err("the hosted door refuses it too");
    assert!(
        hosted_refused.contains("has live instance bindings (inst-bound)"),
        "{hosted_refused}"
    );
    assert_eq!(world.events(), native_events, "nothing appended natively");
    assert_eq!(
        world.hosted.events(),
        hosted_events,
        "nothing appended hosted"
    );
    let [native_after, hosted_after] = world.snapshots();
    assert_eq!(native_after, native_before);
    assert_eq!(hosted_after, hosted_before);
    assert_eq!(native_lease(&world, "line-bound"), None);
    assert_eq!(hosted_lease(&world, "line-bound"), None);

    // C1' gates `release`, which nothing binds: admitted on both hosts, and
    // no instance binds to the line afterwards.
    let mut gates_release = world.charter.clone();
    gates_release.gated_refs = vec!["line-release".into()];
    world.activation("gates-release.json", &gates_release, "owner");
    world.fixture.run(&[
        "activate",
        "--as",
        "owner",
        "--proposal",
        "gates-release.json",
    ]);
    world.hosted.sync(&world);
    assert_eq!(
        native_lease(&world, "line-release").as_deref(),
        Some("norm-gate")
    );
    assert_eq!(
        hosted_lease(&world, "line-release").as_deref(),
        Some("norm-gate")
    );
    assert_eq!(
        world
            .vcs()
            .bind_instance("inst-release", "line-release", "t4")
            .expect("bind"),
        BindOutcome::GatedRef
    );
    assert_eq!(
        world
            .hosted
            .vcs()
            .bind_instance("inst-release", "line-release", "t4")
            .expect("hosted bind"),
        BindOutcome::GatedRef
    );

    // A successor that releases it, and one that names the mainline: each is
    // refused on both hosts, and changes nothing.
    let (native_events, hosted_events) = (world.events(), world.hosted.events());
    let releases = world.charter.clone();
    let mut names_main = gates_release.clone();
    names_main.gated_refs.push(MAINLINE_BRANCH_ID.into());
    for (name, charter, reason) in [
        (
            "releases.json",
            &releases,
            "a successor charter releases a gated line; a gate is never released",
        ),
        (
            "names-main.json",
            &names_main,
            "gated refs name distinct stream lines; the mainline is always gated",
        ),
    ] {
        let signed = world.activation(name, charter, "owner");
        let refused = world
            .fixture
            .refuse(&["activate", "--as", "owner", "--proposal", name]);
        assert!(stderr(&refused).contains(reason), "{}", stderr(&refused));
        let hosted_refused = world
            .hosted
            .leased(json!({"kind": "append", "event": signed}))
            .expect_err("the hosted door refuses it too");
        assert!(hosted_refused.contains(reason), "{hosted_refused}");
        assert_eq!(world.events(), native_events, "{name}");
        assert_eq!(world.hosted.events(), hosted_events, "{name}");
    }
    assert_eq!(
        native_lease(&world, "line-release").as_deref(),
        Some("norm-gate")
    );
    assert_eq!(
        hosted_lease(&world, "line-release").as_deref(),
        Some("norm-gate")
    );
}

/// NP-18: the candidate carries its own proposed policy — a charter without
/// R0's vocabulary, activation handed to the worker, and a declaration that
/// the mainline is ungated — beside the negative mutation. Both hosts' gates
/// ignore it and refuse under the preceding charter, naming R0. Nor can the
/// worker make that policy the ledger's: its activation is refused on both
/// hosts and appends nothing.
#[test]
fn np18_a_candidate_cannot_authorize_its_own_exemption_on_either_host() {
    let world = World::new();
    let mut proposed = world.charter.clone();
    proposed
        .vocabularies
        .retain(|entry| entry.definition.name != "requirement");
    proposed.activation = Some(
        serde_json::from_value(json!({"requires": "authority", "scope": "norm.accept"}))
            .expect("an activation rule"),
    );
    world.line("src/parser.py", MUTATED, "a1", "t3");
    world.line("charter.json", &json!(proposed).to_string(), "a2", "t3");
    world.line(
        "norm/policy.json",
        &json!({"gated_refs": [], "mainline": "ungated", "requirements": {"custody-authorization": "deleted"}, "authority": "worker"}).to_string(),
        "a3",
        "t3",
    );
    world.observe("a3", "a3", &["worker-deny"]);
    for planned in world.planned("a0", "a3") {
        assert_eq!(work(&planned, &world.requirement), ["repair"], "{planned}");
    }
    for detail in world.refused("work", "self-exempting", &[]) {
        assert_eq!(
            detail["requirements"][&world.requirement],
            json!(["repair"]),
            "{detail}"
        );
    }
    for snapshot in world.snapshots() {
        assert_eq!(snapshot["charter"], json!(world.charter));
        assert_eq!(World::records(&snapshot, "requirement").len(), 1);
    }

    // The worker activating that same policy: refused on both hosts.
    let (native_events, hosted_events) = (world.events(), world.hosted.events());
    let signed = world.activation("proposed.json", &proposed, "worker");
    let refused =
        world
            .fixture
            .refuse(&["activate", "--as", "worker", "--proposal", "proposed.json"]);
    assert!(
        stderr(&refused).contains("lacks the charter's authenticated governance authority"),
        "{}",
        stderr(&refused)
    );
    let hosted_refused = world
        .hosted
        .leased(json!({"kind": "append", "event": signed}))
        .expect_err("the hosted door refuses the worker's activation");
    assert!(
        hosted_refused.contains("lacks the charter's authenticated governance authority"),
        "{hosted_refused}"
    );
    assert_eq!(world.events(), native_events);
    assert_eq!(world.hosted.events(), hosted_events);
}

/// NP-19 on both hosts: W repairs the parser on `work`. Before fresh support
/// the repair is refused as `check`; with it, both hosts admit it. The
/// failure and its fixing cut stay inspectable on the object as natively:
/// every observation with the located counterexample, the failing cut's plan,
/// and the fixing cut after the failing one.
#[test]
fn np19_the_repair_is_admitted_only_on_fresh_support_and_stays_inspectable_on_both_hosts() {
    let world = World::new();
    world.observe("a0", "a0", &[]);
    world.line("src/parser.py", MUTATED, "a1", "t3");
    world.observe("a1", "a1", &["worker-deny"]);
    for detail in world.refused("work", "violated", &[]) {
        assert_eq!(
            detail["requirements"][&world.requirement],
            json!(["repair"])
        );
    }
    world.line("src/parser.py", REPAIRED, "a2", "t4");
    for detail in world.refused("work", "unsupported-repair", &[]) {
        assert_eq!(
            detail["requirements"][&world.requirement],
            json!(["check"]),
            "{detail}"
        );
    }
    world.observe("a2", "a2", &[]);
    world.admitted("work", "repaired", &[]);
    assert_eq!(
        world.read(MAINLINE_BRANCH_ID, "src/parser.py").as_deref(),
        Some(REPAIRED)
    );
    assert_eq!(
        world
            .hosted
            .read(MAINLINE_BRANCH_ID, "src/parser.py")
            .as_deref(),
        Some(REPAIRED)
    );

    // Inspectable afterwards, on each host.
    for snapshot in world.snapshots() {
        let observations: Vec<String> = World::records(&snapshot, "local-observation")
            .iter()
            .map(|record| {
                record["fields"]["observation_json"]
                    .as_str()
                    .expect("observation")
                    .to_owned()
            })
            .collect();
        assert_eq!(observations.len(), 3, "{observations:?}");
        assert!(observations
            .iter()
            .any(|observation| observation.contains("worker-deny")
                && observation.contains("\"actual\":true")));
    }
    for planned in world.planned("a0", "a1") {
        assert_eq!(work(&planned, &world.requirement), ["repair"]);
    }
    let chain = |cuts: Option<Vec<whipplescript_store::branches::CutRow>>| {
        cuts.expect("a2 descends from a0")
            .into_iter()
            .map(|cut| cut.cut_id)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        chain(world.vcs().cut_chain("a2", "a0").expect("chain")),
        ["a0", "a1", "a2"]
    );
    assert_eq!(
        chain(
            world
                .hosted
                .vcs()
                .cut_chain("a2", "a0")
                .expect("hosted chain")
        ),
        ["a0", "a1", "a2"],
        "the fixing cut follows the failing one on the object"
    );
}

/// NP-20's second half on both hosts: two offline peers each claim the same
/// future file, `src/new.py`, which exists nowhere. Merged into a native
/// replica and into the hosted object, in either order, both speculative
/// claims survive and the overlap is one conflict naming both.
#[test]
fn np20_offline_claims_on_a_future_file_survive_a_merge_as_one_conflict_on_both_hosts() {
    let world = World::new();
    let (checkpoint, base) = world.history(&world.items());
    world.fixture.write(
        "future.json",
        &json!({"purpose": "add a parser test", "selectors": ["src/new.py"], "mode": "exclusive"}),
    );
    let mut claims = Vec::new();
    let mut histories = Vec::new();
    for (peer, signer) in [
        ("peer-worker.sqlite", "worker"),
        ("peer-owner.sqlite", "owner"),
    ] {
        let items = world.replica(peer, &checkpoint, &base);
        let created = whip_in(
            &world.fixture,
            &items,
            &[
                "--json",
                "norm",
                "create",
                "reservation@1",
                "--as",
                signer,
                "--fields",
                "future.json",
            ],
            None,
        );
        assert!(created.status.success(), "{}", stderr(&created));
        claims.push(event_id(
            &serde_json::from_slice::<Value>(&created.stdout).expect("claim JSON"),
        ));
        histories.push(world.history(&items).1);
    }
    assert_eq!(world.read("line-work", "src/new.py"), None);
    assert_eq!(world.hosted.read("line-work", "src/new.py"), None);

    let native_first = world.replica("fold-a.sqlite", &checkpoint, &histories[0]);
    assert_eq!(world.import(&native_first, &histories[1]), 1);
    let native_second = world.replica("fold-b.sqlite", &checkpoint, &histories[1]);
    assert_eq!(world.import(&native_second, &histories[0]), 1);
    let objects = [Hosted::new(&world.host), Hosted::new(&world.host)];
    objects[0].import(&checkpoint, &histories[0]);
    objects[0].import(&checkpoint, &histories[1]);
    objects[1].import(&checkpoint, &histories[1]);
    objects[1].import(&checkpoint, &histories[0]);

    let snapshot_of = |items: &Path| {
        let output = whip_in(&world.fixture, items, &["--json", "norm", "snapshot"], None);
        assert!(output.status.success(), "{}", stderr(&output));
        serde_json::from_slice::<Value>(&output.stdout).expect("snapshot JSON")["result"]
            ["snapshot"]
            .clone()
    };
    let folds = [
        snapshot_of(&native_first),
        snapshot_of(&native_second),
        objects[0].snapshot(),
        objects[1].snapshot(),
    ];
    let expected = set([claims[0].as_str(), claims[1].as_str()]);
    for (index, snapshot) in folds.iter().enumerate() {
        let held: BTreeSet<String> = World::records(snapshot, "reservation")
            .iter()
            .map(|record| record["id"].as_str().expect("claim").to_owned())
            .collect();
        assert_eq!(held, expected, "fold {index}: both claims survive");
        for record in World::records(snapshot, "reservation") {
            assert_ne!(record["status"], "granted", "fold {index}: {record}");
        }
        let conflicts = snapshot["reservations"]["conflicts"]
            .as_array()
            .unwrap_or_else(|| panic!("fold {index} has no conflicts: {snapshot}"));
        assert_eq!(conflicts.len(), 1, "fold {index}: {conflicts:?}");
        assert_eq!(ids(&conflicts[0]["claims"]), expected, "fold {index}");
        assert_eq!(
            ids(&conflicts[0]["holders"]),
            set(["owner", "worker"]),
            "fold {index}"
        );
        assert_eq!(
            snapshot["reservations"], folds[0]["reservations"],
            "fold {index}"
        );
    }
    // The hosted impact plan carries the same conflict.
    let planned = objects[0].planned("a0", "a0");
    assert_eq!(
        planned["reservation_conflicts"], folds[0]["reservations"]["conflicts"],
        "{planned}"
    );
}

/// NP-22 on both hosts: D0 is folded into R0 by the owner's incorporation
/// and implemented on Q0's support at A0; a dependency edit then contradicts
/// current conformance. The folding stays in the current snapshot of each
/// host. D1, whose intent anchors are merely edited to name R0's subject, is
/// never folded: its edit resets it, and a fold without an incorporation is
/// refused at both hosts' doors.
#[test]
fn np22_intent_edits_never_fold_and_each_host_keeps_the_folding() {
    let world = World::new();
    let decision = |name: &str, subjects: &[&str]| {
        world.fixture.write(
            name,
            &json!({
                "title": "Authorize by role or grant",
                "question": "who may act on custody",
                "course": "owners always, workers when a grant allows",
                "rationale": "least authority",
                "alternatives": ["grants only"],
                "scope": "src/auth.py",
                "consequences": "the parser interprets grants",
                "subjects": subjects,
            }),
        );
    };
    decision("d0.json", &["src/auth.py"]);
    let d0 = event_id(&world.fixture.run(&[
        "create",
        "decision@1",
        "--as",
        "worker",
        "--fields",
        "d0.json",
    ]));
    world
        .fixture
        .run(&["transition", &d0, "accepted", "--as", "owner"]);
    let (d0_revision, r0_revision, basis) = with_view(&world.fixture, &world.items(), |_, view| {
        (
            view.effective_records[&d0].content_head.clone(),
            view.effective_records[&world.requirement]
                .content_head
                .clone(),
            view.relation_family("incorporation")
                .expect("incorporation family")
                .basis,
        )
    });
    world.fixture.write(
        "fold.json",
        &json!({"source": d0_revision, "target": r0_revision}),
    );
    let folding = event_id(&world.fixture.run(&[
        "create",
        "incorporates@1",
        "--as",
        "owner",
        "--fields",
        "fold.json",
        "--family-basis",
        &basis,
        "--references",
        &format!("{d0_revision},{r0_revision}"),
    ]));
    // The family's basis moved with the incorporation; the fold binds it.
    let (r_head, basis) = with_view(&world.fixture, &world.items(), |_, view| {
        (
            view.effective_records[&world.requirement].head.clone(),
            view.relation_family("incorporation")
                .expect("incorporation family")
                .basis,
        )
    });
    world.fixture.run(&[
        "transition",
        &d0,
        "folded",
        "--as",
        "owner",
        "--family-basis",
        &basis,
        "--references",
        &r_head,
    ]);
    world.observe("a0", "a0", &[]);

    // D1: accepted, then its intent anchors edited to name R0's subject and
    // R0 itself. The edit resets it; accepted again, it still cannot fold.
    decision("d1.json", &["src/parser.py"]);
    let d1 = event_id(&world.fixture.run(&[
        "create",
        "decision@1",
        "--as",
        "worker",
        "--fields",
        "d1.json",
    ]));
    world
        .fixture
        .run(&["transition", &d1, "accepted", "--as", "owner"]);
    decision(
        "d1-anchored.json",
        &["src/auth.py", world.requirement.as_str()],
    );
    world
        .fixture
        .run(&["edit", &d1, "--as", "owner", "--fields", "d1-anchored.json"]);
    for snapshot in world.snapshots() {
        let d1_record = World::records(&snapshot, "decision")
            .into_iter()
            .find(|record| record["id"] == d1.as_str())
            .expect("D1");
        assert_eq!(
            d1_record["status"], "proposed",
            "an edit resets: {d1_record}"
        );
    }
    world
        .fixture
        .run(&["transition", &d1, "accepted", "--as", "owner"]);
    world.hosted.sync(&world);
    let basis = with_view(&world.fixture, &world.items(), |_, view| {
        view.relation_family("incorporation")
            .expect("incorporation family")
            .basis
    });
    let (events, hosted_events) = (world.events(), world.hosted.events());
    let refused = world.fixture.refuse(&[
        "transition",
        &d1,
        "folded",
        "--as",
        "owner",
        "--family-basis",
        &basis,
        "--references",
        &r_head,
    ]);
    let (ledger, authority, vocabulary, previous) =
        with_view(&world.fixture, &world.items(), |_, view| {
            let record = &view.records[&d1];
            (
                view.ledger.clone(),
                view.authority_head.clone(),
                record.vocabulary.clone(),
                record.head.clone(),
            )
        });
    let signed = world.signed(
        "owner",
        "fold-d1",
        NormAct::Transition {
            ledger,
            authority: Some(authority),
            vocabulary,
            record: d1.clone(),
            previous,
            status: "folded".into(),
        },
        Some(NormPremises {
            family_basis: Some(basis),
            references: vec![r_head.clone()],
            inventory_frontier: Vec::new(),
        }),
    );
    let hosted_refused = world
        .hosted
        .command(json!({"kind": "append", "event": signed}))
        .expect_err("the hosted door refuses the unwitnessed fold");
    let unwitnessed = "the transition's witness does not hold: no live incorporation relation binds this revision to an effective one";
    assert!(
        stderr(&refused).contains(unwitnessed),
        "{}",
        stderr(&refused)
    );
    assert!(hosted_refused.contains(unwitnessed), "{hosted_refused}");
    assert_eq!(world.events(), events);
    assert_eq!(world.hosted.events(), hosted_events);

    // A dependency edit contradicts current conformance on both hosts; the
    // folding stays in each current snapshot, and D0 stays folded.
    world.line("src/parser.py", MUTATED, "a1", "t3");
    world.observe("a1", "a1", &["worker-deny"]);
    for planned in world.planned("a0", "a1") {
        assert_eq!(work(&planned, &world.requirement), ["repair"]);
    }
    for snapshot in world.snapshots() {
        assert!(snapshot.to_string().contains(&folding), "{snapshot}");
        let statuses: BTreeMap<String, String> = World::records(&snapshot, "decision")
            .iter()
            .map(|record| {
                (
                    record["id"].as_str().expect("id").to_owned(),
                    record["status"].as_str().expect("status").to_owned(),
                )
            })
            .collect();
        assert_eq!(statuses[&d0], "folded", "{statuses:?}");
        assert_eq!(statuses[&d1], "accepted", "{statuses:?}");
    }
}
