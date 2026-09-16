use super::*;
use whipplescript_custody::client::UnixSocketTransport;

#[test]
fn norm_cli_hosted_protected_enqueue_checks_installed_profile() {
    use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
    use whipplescript_kernel::norm_execution::fixtures as execution;
    use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
    use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
    use whipplescript_store::content::ContentStore;
    use whipplescript_store::items::WorkItemStore;
    use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};

    {
        let actual = false;
        let fixture = Fixture::new();
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
        let record = created["result"]["event_id"]
            .as_str()
            .expect("requirement id");
        fixture.run(&["transition", "N-1", "accepted", "--as", "owner"]);

        let transport = UnixSocketTransport::new(fixture.root.join("custody.sock"));
        let key = NormCustodyKey::new(
            "owner".into(),
            CredentialName::new("norm/owner").expect("credential"),
            NormCustodyVersion::ImmutableLocal,
            &transport,
        )
        .expect("custody key");
        let verifier = NormGovernanceVerifier::new(
            vec![NormPrincipalBinding {
                actor: key.actor().clone(),
                verifier: &key,
            }],
            [("worker".into(), "owner".into())].into(),
        )
        .expect("verifier");
        let ledger = WorkItemStore::open(fixture.root.join("items.sqlite")).expect("ledger");
        let mut branches =
            BranchStore::open(fixture.root.join("branches.sqlite")).expect("branches");
        let content = ContentStore::open(fixture.root.join("content.sqlite")).expect("content");
        branches.ensure_mainline("t0").expect("mainline");
        let source = if actual {
            "def allow(user): return True"
        } else {
            "def allow(user): return False"
        };
        let file = content.put(source.as_bytes()).expect("source");
        let manifest = content
            .put(json!({"main.py":file}).to_string().as_bytes())
            .expect("manifest");
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
            .expect("cut");
        let artifact =
            capture_cut(&branches, &content, "cut", ArtifactLimits::default()).expect("artifact");
        use ring::signature::KeyPair;
        let public = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[1; 32])
            .expect("fixture public key");
        let public_key_hex: String = public
            .public_key()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let trust = json!({"bindings":[],"public_bindings":[{"actor":key.actor(),"public_key_hex":public_key_hex}],"creation_grants":[]}).to_string();
        norm_hosted_enqueue_fixture(
            &ledger,
            &verifier,
            &trust,
            &artifact,
            record,
            Some(&method.runtime),
        );
    }
}
