//! Real hosted execution with native custody kept alive for publication signing.
use super::*;
use ring::signature::KeyPair;
use whipplescript_custody::client::UnixSocketTransport;
use whipplescript_kernel::{
    exec_http::sha256_hex,
    norm_custody::{NormCustodyKey, NormCustodyVersion},
    norm_execution::fixtures as execution,
    norm_runner::PythonEngine,
};
use whipplescript_store::items::WorkItemStore;

/// The check a physical case installs and the files of the cut it runs on,
/// for the case whose run passes (`actual` false) or fails (`actual` true).
struct PhysicalCase {
    support: Value,
    /// The cases the run must refute.
    counterexamples: Vec<&'static str>,
    proposition: &'static str,
    subject: &'static str,
    files: Vec<(&'static str, String)>,
}

#[test]
#[ignore = "requires Docker, Wrangler, built worker WASM and the pinned reactor"]
fn norm_cli_hosted_protected_publication_with_real_custody() {
    run_physical(|method, actual| {
        let source = if actual {
            "def allow(user):\n    print(\"{\\\"kind\\\":\\\"case\\\",\\\"actual\\\":false}\")\n    return True"
        } else {
            "def allow(user): return False"
        };
        let mut support = execution::template();
        support["method"] = json!(method);
        PhysicalCase {
            support,
            counterexamples: if actual { vec!["deny"] } else { Vec::new() },
            proposition: "unknown denied",
            subject: "main.py",
            files: vec![("main.py", source.to_owned())],
        }
    });
}

/// S1's check itself, physically: Q0's four cases over the authorization
/// demo's workspace, passing at A0 and failing `worker-deny` once the parser
/// is mutated, executed in a real container and published through custody.
#[test]
#[ignore = "requires Docker, Wrangler, built worker WASM and the pinned reactor"]
fn norm_cli_hosted_protected_q0_with_real_custody() {
    const MUTATED: &str = "def grant_allows(grant):\n    return grant in (\"allow\", \"deny\")\n";
    let demo = |path: &str| -> String {
        match path {
            "checks/q0.json" => {
                include_str!("../../../../examples/authorization-demo/checks/q0.json")
            }
            "src/auth.py" => include_str!("../../../../examples/authorization-demo/src/auth.py"),
            "src/parser.py" => {
                include_str!("../../../../examples/authorization-demo/src/parser.py")
            }
            other => panic!("the demo has no {other}"),
        }
        .to_owned()
    };
    run_physical(|host_method, actual| {
        let q0: Value = serde_json::from_str(&demo("checks/q0.json")).expect("Q0");
        let cases = q0["cases"].as_array().expect("Q0 cases");
        let method = whipplescript_kernel::norm_runner::PythonCallMethod {
            runtime: host_method.runtime.clone(),
            module: q0["module"].as_str().expect("module").into(),
            function: q0["function"].as_str().expect("function").into(),
            cases: cases
                .iter()
                .map(|case| whipplescript_kernel::norm_runner::PythonCase {
                    id: case["id"].as_str().expect("id").into(),
                    args: vec![case["role"].clone(), case["grant"].clone()],
                    kwargs: std::collections::BTreeMap::new(),
                })
                .collect(),
        };
        let required: Vec<Value> = cases
            .iter()
            .map(|case| {
                json!({
                    "id": case["id"],
                    "assertion": format!(
                        "authorize({}, {}) is {}",
                        case["role"].as_str().expect("role"),
                        case["grant"].as_str().expect("grant"),
                        case["expected"]
                    ),
                    "expected": case["expected"],
                })
            })
            .collect();
        let parser = if actual {
            MUTATED.to_owned()
        } else {
            demo("src/parser.py")
        };
        PhysicalCase {
            counterexamples: if actual {
                vec!["worker-deny"]
            } else {
                Vec::new()
            },
            support: json!({
                "protocol": "whipplescript.norm.python-calls-support/v1",
                "method": method,
                "cases": required,
            }),
            proposition: "an owner is always authorized, and a worker only under an allowing grant",
            subject: "src/auth.py",
            files: vec![
                ("checks/q0.json", demo("checks/q0.json")),
                ("src/auth.py", demo("src/auth.py")),
                ("src/parser.py", parser),
            ],
        }
    });
}

/// Run the physical harness over a passing and a failing case of one check.
fn run_physical(
    case: impl Fn(&whipplescript_kernel::norm_runner::PythonCallMethod, bool) -> PhysicalCase,
) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let reactor = root.join("target/norm-cpython-observer.wasm");
    let mut method = execution::method();
    method.runtime.executable = "/usr/local/bin/whip".into();
    method.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/hosted-norm/runtime.wasm".into(),
        artifact_sha256: sha256_hex(&std::fs::read(&reactor).expect("pinned reactor")),
    };
    let fixtures = [Fixture::new(), Fixture::new()];
    let mut cases = Vec::new();
    for (fixture, actual) in fixtures.iter().zip([false, true]) {
        let mut charter = whipplescript_store::norm::NormCharter::bundled().expect("charter");
        charter
            .vocabularies
            .push(execution::observation_vocabulary());
        charter.owner_scopes.push("observe.publish".into());
        let roles: Vec<Value> = charter
            .vocabularies
            .iter()
            .filter_map(|entry| {
                let interpretation = match entry.definition.name.as_str() {
                    "obligation" => "context",
                    "local-observation" => "published_execution",
                    _ => return None,
                };
                let vocabulary =
                    whipplescript_core::vocabulary::Vocabulary::new(entry.definition.clone())
                        .expect("vocabulary");
                Some(json!({"vocabulary":vocabulary.reference(),"interpretation":interpretation}))
            })
            .collect();
        assert_eq!(roles.len(), 2);
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
        let physical = case(&method, actual);
        fixture.write("fields.json", &json!({"name":"allow", "proposition":physical.proposition, "domain":"workspace", "subject":physical.subject, "support_contract":physical.support.to_string()}));
        let created = fixture.run(&[
            "create",
            "obligation@1",
            "--as",
            "owner",
            "--fields",
            "fields.json",
        ]);
        fixture.run(&["transition", "N-1", "accepted", "--as", "owner"]);
        let ledger = WorkItemStore::open(fixture.root.join("items.sqlite")).expect("ledger");
        let transport = UnixSocketTransport::new(fixture.root.join("custody.sock"));
        let mut bindings = Vec::new();
        for (principal, byte) in [("owner", 1), ("worker", 2)] {
            let key = NormCustodyKey::new(
                principal.into(),
                CredentialName::new(&format!("norm/{principal}")).expect("credential"),
                NormCustodyVersion::ImmutableLocal,
                &transport,
            )
            .expect("custody key");
            let public = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[byte; 32])
                .expect("fixture public key");
            let public_key_hex: String = public
                .public_key()
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            bindings.push(json!({"actor":key.actor(), "public_key_hex":public_key_hex}));
        }
        // The same content-addressing scheme the owning ContentStore uses.
        let content =
            whipplescript_store::content::ContentStore::open(fixture.root.join("content.sqlite"))
                .expect("content");
        let mut blobs = Vec::new();
        let mut entries = serde_json::Map::new();
        for (path, source) in &physical.files {
            let file = content.put(source.as_bytes()).expect("source");
            blobs.push(json!({"id":file,"body":source,"byte_len":source.len()}));
            entries.insert((*path).to_owned(), json!(file));
        }
        let manifest_body = Value::Object(entries).to_string();
        let manifest = content.put(manifest_body.as_bytes()).expect("manifest");
        blobs.push(json!({"id":manifest,"body":manifest_body,"byte_len":manifest_body.len()}));
        cases.push(json!({
            "actual":actual, "counterexamples":physical.counterexamples, "requirement":created["result"]["event_id"],
            "planning":{"capability":"observer","roles":roles},
            "events":ledger.export_events().expect("history"),
            "checkpoint":ledger.norm_checkpoint().expect("checkpoint").expect("pin"),
            "public_bindings":bindings,
            "signing":{"socket":fixture.root.join("custody.sock"),"trust":fixture.trust},
            "artifacts":{"blobs":blobs,
                "cuts":[{"cut_id":"cut","change_id":"cut","branch_id":whipplescript_store::branches::MAINLINE_BRANCH_ID,"manifest_hash":manifest,"recorded_at":"t1"},{"cut_id":"same-content","change_id":"same-content","branch_id":whipplescript_store::branches::MAINLINE_BRANCH_ID,"manifest_hash":manifest,"recorded_at":"t2"}]}
        }));
    }
    let evidence = root.join("target").join(format!(
        "norm-hosted-publication-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&evidence).expect("evidence directory");
    let vector = evidence.join("input.json");
    std::fs::write(&vector, json!({"runtime":method.runtime,"reactor":reactor,"cases":cases,
        "scripts":[{"name":"observer","argv":[method.runtime.executable,"executor","observe-norm","{script}"],"sha256":sha256_hex(method.adapter().as_bytes()),"body":method.adapter(),"hermetic":false}]
    }).to_string()).expect("physical input");
    let status = Command::new("python3")
        .arg(root.join(
            "crates/whipplescript-host-do/worker/scripts/check-norm-publication-container.py",
        ))
        .arg(&vector)
        .arg(env!("CARGO_BIN_EXE_whip"))
        .status()
        .expect("physical hosted publication harness");
    assert!(
        status.success(),
        "hosted publication failed; inspect {}",
        evidence.display()
    );
}
