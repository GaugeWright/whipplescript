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

#[test]
#[ignore = "requires Docker, Wrangler, built worker WASM and the pinned reactor"]
fn norm_cli_hosted_protected_publication_with_real_custody() {
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
        let source = if actual {
            "def allow(user):\n    print(\"{\\\"kind\\\":\\\"case\\\",\\\"actual\\\":false}\")\n    return True"
        } else {
            "def allow(user): return False"
        };
        // The same content-addressing scheme the owning ContentStore uses.
        let content =
            whipplescript_store::content::ContentStore::open(fixture.root.join("content.sqlite"))
                .expect("content");
        let file = content.put(source.as_bytes()).expect("source");
        let manifest_body = json!({"main.py":file}).to_string();
        let manifest = content.put(manifest_body.as_bytes()).expect("manifest");
        cases.push(json!({
            "actual":actual, "requirement":created["result"]["event_id"],
            "planning":{"capability":"observer","roles":roles},
            "events":ledger.export_events().expect("history"),
            "checkpoint":ledger.norm_checkpoint().expect("checkpoint").expect("pin"),
            "public_bindings":bindings,
            "signing":{"socket":fixture.root.join("custody.sock"),"trust":fixture.trust},
            "artifacts":{"blobs":[{"id":file,"body":source,"byte_len":source.len()}, {"id":manifest,"body":manifest_body,"byte_len":manifest_body.len()}],
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
