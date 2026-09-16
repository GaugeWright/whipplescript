//! Real custody, CLI enqueue, managed Docker execution and signed publication.
use super::*;
use whipplescript::native_executor::{NativeNormHost, NativeRuntimeImage, RuntimeImageRequest};
use whipplescript_kernel::{
    exec_http::sha256_hex, norm_execution::fixtures as execution, norm_runner::PythonEngine,
    ProgramVersionInput, RuntimeKernel,
};
use whipplescript_store::{
    branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID},
    content::ContentStore,
    items::WorkItemStore,
    CapabilityBinding, CapabilitySchemaRegistration, ScriptCapabilityRegistration, SqliteStore,
};

struct Cleanup {
    endpoint: String,
    image: String,
    instances: Vec<(PathBuf, String)>,
}
impl Cleanup {
    fn docker(&self, args: &[&str]) -> Output {
        Command::new("docker")
            .args(["--host", &self.endpoint])
            .args(args)
            .output()
            .expect("physical publication Docker client")
    }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        for (path, instance) in &self.instances {
            if let Ok(store) = SqliteStore::open(path) {
                for run in store.list_runs(instance).unwrap_or_default() {
                    if let Ok(Some((_, owner))) = store.native_executor_owner(instance, &run.run_id)
                    {
                        let _ = self.docker(&[
                            "container",
                            "rm",
                            "--force",
                            "--volumes",
                            &owner.owner_id,
                        ]);
                    }
                    let _ =
                        self.docker(&["volume", "rm", &format!("whip-controller-{}", run.run_id)]);
                }
            }
        }
        let _ = self.docker(&["image", "rm", &self.image]);
    }
}
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("physical publication command JSON")
}

#[test]
#[ignore = "requires the production executor image, pinned reactor and Docker"]
fn norm_cli_protected_publication_with_real_custody() {
    let endpoint = std::env::var("WHIP_TEST_DOCKER_ENDPOINT").expect("physical Docker endpoint");
    let base = std::env::var("WHIP_TEST_EXECUTOR_IMAGE").expect("physical executor image");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let source = root.join("target/norm-cpython-observer.wasm");
    let daemon = Command::new("docker")
        .args(["--host", &endpoint, "info", "--format", "{{.ID}}"])
        .output()
        .expect("read daemon identity");
    assert!(daemon.status.success());
    let mut method = execution::method();
    method.runtime.executable = "/opt/whip-publication/observer".into();
    method.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/whip-publication/runtime.wasm".into(),
        artifact_sha256: sha256_hex(&std::fs::read(&source).expect("pinned reactor")),
    };
    let installed: NativeRuntimeImage = RuntimeImageRequest {
        endpoint: endpoint.clone(),
        daemon_id: String::from_utf8(daemon.stdout)
            .expect("daemon ID")
            .trim()
            .into(),
        base_image: base,
        build_root: root.join("target/norm-publication-images"),
        artifact_source: source,
        runtime: method.runtime.clone(),
    }
    .install()
    .expect("install protected publication runtime");
    // Keep the custody fixtures alive until cleanup has inspected their runtime journals.
    let fixtures = [Fixture::new(), Fixture::new()];
    let mut cleanup = Cleanup {
        endpoint: endpoint.clone(),
        image: installed.image_id.clone(),
        instances: vec![],
    };
    for (fixture, actual) in fixtures.iter().zip([false, true]) {
        let mut charter = whipplescript_store::norm::NormCharter::bundled().expect("charter");
        charter
            .vocabularies
            .push(execution::observation_vocabulary());
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
        let mut support = execution::template();
        support["method"] = json!(method);
        fixture.write("fields.json", &json!({"name":"allow", "proposition":"unknown denied", "domain":"workspace", "subject":"main.py", "support_contract":support.to_string()}));
        let created = fixture.run(&[
            "create",
            "obligation@1",
            "--as",
            "owner",
            "--fields",
            "fields.json",
        ]);
        let requirement = created["result"]["event_id"]
            .as_str()
            .expect("requirement identity");
        fixture.run(&["transition", "N-1", "accepted", "--as", "owner"]);
        let mut branches =
            BranchStore::open(fixture.root.join("branches.sqlite")).expect("branches");
        branches.ensure_mainline("t0").expect("mainline");
        let content = ContentStore::open(fixture.root.join("content.sqlite")).expect("content");
        let file = content
            .put(
                if actual {
                    "def allow(user): return True"
                } else {
                    "def allow(user): return False"
                }
                .as_bytes(),
            )
            .expect("candidate source");
        let manifest = content
            .put(json!({"main.py":file}).to_string().as_bytes())
            .expect("candidate manifest");
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
                recorded_at: "t1",
            })
            .expect("candidate cut");
        let path = fixture.root.join("runtime.sqlite");
        let mut kernel = RuntimeKernel::new(SqliteStore::open(&path).expect("runtime"));
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "protected-publication",
                source_hash: "fixture",
                ir_hash: "fixture",
                compiler_version: "fixture",
                ir_snapshot: None,
            })
            .expect("program version");
        let instance = kernel.create_instance(&version, "{}").expect("instance");
        cleanup.instances.push((path.clone(), instance.clone()));
        kernel
            .store()
            .register_script_capability(ScriptCapabilityRegistration {
                name: "observer",
                argv_json: &json!([
                    method.runtime.executable,
                    "executor",
                    "observe-norm",
                    "{script}"
                ])
                .to_string(),
                sha256: &sha256_hex(method.adapter().as_bytes()),
                env_json: "{}",
                hermetic: false,
                body: method.adapter(),
            })
            .expect("observer registration");
        kernel
            .store()
            .register_capability_schema(CapabilitySchemaRegistration {
                capability: "script.observer",
                description: "fixture grant",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .expect("capability schema");
        kernel
            .store()
            .bind_capability(CapabilityBinding {
                binding_id: "observer",
                program_id: Some(&version.program_id),
                capability: "script.observer",
                provider: "builtin-script",
                config_json: "{}",
            })
            .expect("program grant");
        fixture.write(
            "host.json",
            &json!(NativeNormHost {
                protocol: "whipplescript.exec.native-norm-host/v1".into(),
                endpoint: endpoint.clone(),
                installed: installed.clone()
            }),
        );
        let enqueue = || {
            fixture
                .command(&[
                    "enqueue-observation",
                    &instance,
                    requirement,
                    "cut",
                    "--effect",
                    "observe",
                    "--capability",
                    "observer",
                    "--as",
                    "owner",
                ])
                .env("WHIPPLESCRIPT_STORE", &path)
                .env(
                    "WHIPPLESCRIPT_NATIVE_NORM_RUNTIME",
                    fixture.root.join("host.json"),
                )
                .output()
                .expect("enqueue protected observation")
        };
        let acknowledgment = success(enqueue());
        let worker = success(
            Command::new(env!("CARGO_BIN_EXE_whip"))
                .env_clear()
                .env("PATH", std::env::var_os("PATH").expect("physical PATH"))
                .env("WHIPPLESCRIPT_STORE", &path)
                .env(
                    "WHIPPLESCRIPT_NATIVE_NORM_RUNTIME",
                    fixture.root.join("host.json"),
                )
                .args(["--json", "worker", &instance, "--once"])
                .output()
                .expect("managed worker"),
        );
        assert_eq!(worker["ran_effects"], 1);
        assert_eq!(worker["native_norm_pending"], 0);
        let runs = kernel.store().list_runs(&instance).expect("completed runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, if actual { "failed" } else { "completed" });
        let run = &runs[0].run_id;
        let metadata: Value =
            serde_json::from_str(&runs[0].metadata_json).expect("terminal metadata");
        assert_eq!(metadata["executor_transport"], "native-managed");
        assert!(
            whipplescript_kernel::exec_lifetime::proofs(kernel.store(), &instance)
                .expect("verified closure")
                .contains_key(run)
        );
        let (_, owner) = kernel
            .store()
            .native_executor_owner(&instance, run)
            .expect("original owner")
            .expect("retained owner");
        assert!(!cleanup
            .docker(&["container", "inspect", &owner.owner_id])
            .status
            .success());
        let publish = |principal: &str| {
            fixture
                .command(&[
                    "publish-observation",
                    &instance,
                    run,
                    "local-observation@1",
                    "--as",
                    principal,
                ])
                .env("WHIPPLESCRIPT_STORE", &path)
                .output()
                .expect("publish protected observation")
        };
        let ledger = WorkItemStore::open(fixture.root.join("items.sqlite")).expect("ledger");
        let before = ledger.export_events().expect("ledger events");
        let journal = kernel
            .store()
            .list_events(&instance)
            .expect("execution journal");
        let wrong = publish("worker");
        assert!(!wrong.status.success());
        assert!(String::from_utf8_lossy(&wrong.stderr).contains("publisher"));
        assert_eq!(ledger.export_events().expect("unchanged ledger"), before);
        assert_eq!(
            kernel
                .store()
                .list_events(&instance)
                .expect("unchanged runtime"),
            journal
        );
        let published = success(publish("owner"));
        assert_eq!(
            published["observation"]["observation_integrity"],
            json!({"kind":"protected_interpreter"})
        );
        assert_eq!(
            published["observation"]["judgment"]["outcome"],
            if actual { "fail" } else { "pass" }
        );
        assert_eq!(
            published["observation"]["report"]["observations"][0]["actual"],
            json!(actual)
        );
        assert_eq!(
            published["observation"]["judgment"]["counterexamples"]
                .as_array()
                .expect("counterexamples")
                .len(),
            usize::from(actual)
        );
        let after = ledger.export_events().expect("published ledger");
        assert_eq!(after.len(), before.len() + 1);
        let journal = kernel
            .store()
            .list_events(&instance)
            .expect("publication journal");
        drop(kernel);
        assert_eq!(success(publish("owner")), published);
        assert_eq!(success(enqueue()), acknowledgment);
        let cold = SqliteStore::open(&path).expect("cold runtime");
        assert_eq!(
            cold.list_runs(&instance).expect("one original run").len(),
            1
        );
        assert_eq!(
            cold.list_events(&instance).expect("retained journal"),
            journal
        );
        assert_eq!(
            ledger.export_events().expect("one signed observation"),
            after
        );
        rusqlite::Connection::open(fixture.root.join("branches.sqlite"))
            .expect("artifact database")
            .execute("DELETE FROM cuts WHERE cut_id = 'cut'", [])
            .expect("remove original artifact");
        assert!(!publish("owner").status.success());
        assert_eq!(
            ledger.export_events().expect("refused ledger unchanged"),
            after
        );
        assert_eq!(
            cold.list_events(&instance)
                .expect("refused runtime unchanged"),
            journal
        );
        println!("protected CLI publication: actual={actual}, real custody, managed execution, closure, original judgment and cold acknowledgment verified");
    }
}
