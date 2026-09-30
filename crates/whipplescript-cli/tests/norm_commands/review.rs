use super::*;
use whipplescript_store::branches::flowing_admission::RetainFlowingAttemptOutcome;
use whipplescript_store::branches::flowing_fence::{
    FlowingFence, FlowingSourceKind, OpenFlowingSource,
};
use whipplescript_store::branches::flowing_sources::{
    DeclareContribution, FlowingSources, PinPrivateCut,
};
use whipplescript_store::branches::{BranchStore, Branches, MAINLINE_BRANCH_ID};
use whipplescript_store::source_review::ReviewStore;
use whipplescript_store::source_review_native::{NativeCandidateRequest, NativeUpload};
use whipplescript_store::vcs::{
    native_dependency_basis_digest, native_read_basis_digest, FlowingSelectionOutcome,
    NativeCandidateOutcome, NativeWorkspaceVcs,
};
use whipplescript_store::SqliteStore;

fn candidate(fixture: &Fixture) -> String {
    let mut vcs = NativeWorkspaceVcs::open(
        fixture.root.join("branches.sqlite"),
        fixture.root.join("content.sqlite"),
    )
    .expect("open native fixture VCS");
    let mut branches = BranchStore::open(fixture.root.join("branches.sqlite"))
        .expect("open native fixture branch store");
    seed_candidate(&mut vcs, &mut branches)
}

fn seed_candidate<B, C>(
    vcs: &mut whipplescript_store::vcs::WorkspaceVcs<B, C>,
    branches: &mut B,
) -> String
where
    B: Branches
        + FlowingFence
        + FlowingSources
        + whipplescript_store::branches::flowing_admission::FlowingAdmissions,
    C: whipplescript_store::content::ContentBlobs,
{
    vcs.init("t0").expect("initialize candidate mainline");
    vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
        .expect("create candidate twig");
    branches
        .open_flowing_source(&OpenFlowingSource {
            source_branch_id: "twig".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Twig,
            owner: "coordinator".into(),
            opened_at: "t1".into(),
        })
        .expect("open source incarnation");
    vcs.write(
        "twig",
        "main.py",
        Some("def allow(x): return False\n"),
        "source",
        "t2",
    )
    .expect("write candidate source");
    let cut = branches
        .get_cut("source")
        .expect("read source cut")
        .expect("source cut exists");
    branches
        .pin_private_cut(PinPrivateCut {
            pin_id: "pin",
            twig_branch_id: "twig",
            cut_id: "source",
            manifest_hash: &cut.manifest_hash,
            principal: "author",
            retained_at: "t3",
        })
        .expect("pin private source");
    branches
        .declare_contribution(DeclareContribution {
            unit_id: "unit",
            pin_id: "pin",
            principal: "author",
            intent: "change",
            read_basis_digest: &native_read_basis_digest(None, None),
            dependency_basis_digest: &native_dependency_basis_digest(&[]),
            scope_digest: "scope",
            declared_at: "t3",
        })
        .expect("declare contribution");
    let FlowingSelectionOutcome::Selected(selected) = vcs
        .select_private_changes(
            "pin",
            &whipplescript_store::selection::parse("path(main.py)").expect("parse path selection"),
        )
        .expect("select contribution changes")
    else {
        panic!("selection")
    };
    vcs.bind_private_selection("unit", &selected, "t3")
        .expect("bind private selection");
    let mut reviews = ReviewStore::open(":memory:").expect("open review store");
    reviews
        .create_native_contribution("review", "author", "change", MAINLINE_BRANCH_ID, &[])
        .expect("create reviewed contribution");
    reviews
        .upload_native_revision(
            branches,
            NativeUpload {
                contribution_id: "review",
                upload_id: "upload",
                actor: "author",
                source_branch_id: "twig",
                source_cut_id: "source",
                unit_ids: &["unit"],
            },
        )
        .expect("upload reviewed revision");
    let NativeCandidateOutcome::Prepared(prepared) = reviews
        .prepare_native_candidate(
            vcs,
            NativeCandidateRequest {
                contribution_id: "review",
                sequence: 1,
                expected_trunk_cut_id: None,
                candidate_cut_id: "candidate",
                actor: "coordinator",
                recorded_at: "t4",
            },
        )
        .expect("prepare candidate cut")
    else {
        panic!("candidate")
    };
    assert!(matches!(
        vcs.retain_review_attempt("attempt", &prepared.candidate_witness_digest, "t4")
            .expect("retain candidate attempt"),
        RetainFlowingAttemptOutcome::Retained(_)
    ));
    prepared.candidate_witness_digest
}

fn host(fixture: &Fixture) -> (Value, PathBuf) {
    let mut runtime = whipplescript_kernel::norm_execution::fixtures::method().runtime;
    runtime.engine = whipplescript_kernel::norm_runner::PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/reactor.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    runtime.executable = "/usr/local/bin/whip".into();
    fixture.write("runtime-host.json", &json!({
        "protocol":"whipplescript.exec.native-norm-host/v1", "endpoint":"unix:///no-query-executor",
        "installed":{"protocol":"whipplescript.exec.native-runtime-image/v1","daemon_id":"fixture-daemon",
        "base_image":format!("sha256:{}", "b".repeat(64)),"image_id":format!("sha256:{}", "c".repeat(64)),"runtime":runtime}
    }));
    (
        json!({"capability":"observer","roles":[]}),
        fixture.root.join("runtime-host.json"),
    )
}

#[test]
fn review_plan_cli_returns_blockers_without_creating_work_or_running_checks() {
    let fixture = Fixture::new();
    fixture.run(&["bootstrap", "--as", "owner", "--creator", "worker"]);
    fixture.write("fields.json", &json!({"name":"allow","proposition":"unknown denied","domain":"workspace","subject":"main.py"}));
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
    let witness = candidate(&fixture);
    drop(SqliteStore::open(fixture.root.join("runtime.sqlite")).unwrap());
    let (planning, runtime_host) = host(&fixture);
    let before = fixture.run(&["export"]);
    let query = || {
        admission::whip(
            &fixture,
            &["--json", "review", "plan", &witness, "attempt"],
            Some((&planning, &runtime_host)),
        )
    };
    let first = query();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let identity = first["identity"].as_str().unwrap();
    assert_eq!(identity.len(), "sha256:".len() + 64);
    let second = query();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(
        first, second,
        "unchanged semantic premises reproduce the plan"
    );
    assert!(first["judgment"]["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["scope"] == "home/reference-population"));
    assert!(first["judgment"]["obligations"]
        .as_object()
        .unwrap()
        .values()
        .any(|duty| duty["record"] == requirement));
    assert_eq!(fixture.run(&["export"]), before);
    assert!(
        SqliteStore::open_read_only(fixture.root.join("runtime.sqlite"))
            .unwrap()
            .list_instances()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        BranchStore::open_read_only(fixture.root.join("branches.sqlite"))
            .unwrap()
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id,
        None
    );
    for args in [
        vec!["review", "plan", &witness, "other-attempt"],
        vec!["review", "plan", "other-witness", "attempt"],
    ] {
        let out = admission::whip(&fixture, &args, Some((&planning, &runtime_host)));
        assert!(!out.status.success());
    }
    assert_eq!(fixture.run(&["export"]), before);
    hosted_reader(&fixture, &witness, &first, &planning, &runtime_host);
}

fn hosted_reader(
    fixture: &Fixture,
    witness: &str,
    native: &Value,
    planning: &Value,
    runtime_host: &std::path::Path,
) {
    use ring::signature::KeyPair;
    use whipplescript_custody::client::UnixSocketTransport;
    use whipplescript_host_do::do_branches::{DoBranches, DoContentBlobs};
    use whipplescript_host_do::do_store::{
        test_support::RusqliteDoSql, DoSql, DoSqliteStore, SqlValue,
    };
    use whipplescript_host_do::source_planning::execute_installed_hosted_source_plan;
    use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
    use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
    use whipplescript_store::norm_commands::NormCommandStore;
    use whipplescript_store::RuntimeStore;
    #[derive(Clone)]
    struct ReadsOnly(RusqliteDoSql, std::rc::Rc<std::cell::Cell<usize>>);
    impl DoSql for ReadsOnly {
        fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
            self.1.set(self.1.get() + 1);
            Err("query attempted a write".into())
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            self.0.query(sql, params)
        }
    }
    let sql = RusqliteDoSql::with_store_schema();
    let mut branches = DoBranches::new(sql.clone()).expect("open hosted fixture branches");
    let mut vcs = whipplescript_store::vcs::WorkspaceVcs::from_parts(
        DoBranches::new(sql.clone()).expect("open hosted VCS branches"),
        DoContentBlobs::new(sql.clone()).expect("open hosted content store"),
    );
    let hosted_witness = seed_candidate(&mut vcs, &mut branches);
    assert_eq!(
        hosted_witness, witness,
        "both owning candidate builders retain the same subject"
    );
    let transport = UnixSocketTransport::new(fixture.root.join("custody.sock"));
    let key = NormCustodyKey::new(
        "owner".into(),
        CredentialName::new("norm/owner").expect("parse fixture credential name"),
        NormCustodyVersion::ImmutableLocal,
        &transport,
    )
    .expect("open fixture custody key");
    let verifier = NormGovernanceVerifier::new(
        vec![NormPrincipalBinding {
            actor: key.actor().clone(),
            verifier: &key,
        }],
        [("worker".into(), "owner".into())].into(),
    )
    .expect("construct fixture governance verifier");
    let ledger = whipplescript_store::items::WorkItemStore::open_read_only(
        fixture.root.join("items.sqlite"),
    )
    .expect("open native fixture norm ledger");
    let mut store = DoSqliteStore::new(sql.clone());
    store
        .pin_norm_checkpoint(
            &ledger
                .norm_checkpoint()
                .expect("read native checkpoint")
                .expect("native checkpoint exists"),
        )
        .expect("pin hosted norm checkpoint");
    store
        .import_norm(
            &ledger.export_events().expect("read native norm events"),
            &verifier,
        )
        .expect("import authenticated hosted history");
    let public = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[1; 32])
        .expect("construct fixture signing key");
    let public_hex: String = public
        .public_key()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let trust = json!({"bindings":[],"public_bindings":[{"actor":key.actor(),"public_key_hex":public_hex}],"creation_grants":[]}).to_string();
    let runtime_host: Value = serde_json::from_slice(
        &std::fs::read(runtime_host).expect("read installed runtime configuration"),
    )
    .expect("parse installed runtime configuration");
    let runtime = runtime_host["installed"]["runtime"].clone();
    let deployment = json!({"planning":planning.to_string(),"runtime":runtime.to_string(),
        "deployed_image":runtime_host["installed"]["image_id"],"image_binding":json!({
            "protocol":"whipplescript.exec.runtime-image/v1","image_id":runtime_host["installed"]["image_id"],"runtime":runtime
        }).to_string(),"time_basis":"host-owned-query"}).to_string();
    let request = json!({"protocol":"whipplescript.source-admission/v1","candidate_witness_digest":witness,"attempt_id":"attempt"});
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let reads = ReadsOnly(sql.clone(), calls.clone());
    let events_before = store
        .export_events()
        .expect("read hosted events before query");
    let query =
        |body: &str| execute_installed_hosted_source_plan(&reads, &trust, body, &deployment);
    let hosted: Value =
        serde_json::from_str(&query(&request.to_string()).expect("derive hosted source plan"))
            .expect("parse hosted source plan");
    assert_eq!(hosted["judgment"]["subject"], native["judgment"]["subject"]);
    let comparison = |value: &Value| {
        let mut duties = value["judgment"]["obligations"].clone();
        for duty in duties
            .as_object_mut()
            .expect("obligations are an object")
            .values_mut()
        {
            let query = duty["support"]["query"]
                .as_object_mut()
                .expect("support query is an object");
            query.remove("policy");
            query.remove("time_basis");
        }
        duties
    };
    assert_eq!(comparison(&hosted), comparison(native));
    assert_ne!(
        hosted["judgment"]["norm"]["plan"]["policy"], native["judgment"]["norm"]["plan"]["policy"],
        "the native host also supports Buck2; the hosted policy cannot claim that installation"
    );
    assert_eq!(
        hosted["judgment"]["references"],
        native["judgment"]["references"]
    );
    assert_eq!(
        hosted["judgment"]["blockers"],
        native["judgment"]["blockers"]
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &query(&request.to_string()).expect("repeat hosted source plan")
        )
        .expect("parse repeated hosted source plan"),
        hosted
    );
    for field in ["policy", "coverage", "checks", "frontier", "store"] {
        let mut forged = request.clone();
        forged[field] = "caller supplied".into();
        assert!(query(&forged.to_string()).is_err());
    }
    let mut wrong = request.clone();
    wrong["protocol"] = "another-protocol".into();
    assert!(query(&wrong.to_string())
        .expect_err("reject another source query protocol")
        .contains("unsupported source admission query protocol"));
    let mut oversized = request.to_string();
    oversized.push_str(&" ".repeat(65_537));
    assert!(query(&oversized)
        .expect_err("reject oversized source query")
        .contains("exceeds 64 KiB"));
    let mut wrong = request;
    wrong["attempt_id"] = "other-attempt".into();
    assert!(query(&wrong.to_string()).is_err());
    assert_eq!(
        calls.get(),
        0,
        "the hosted query cannot initialize schema or write journal state"
    );
    assert_eq!(
        store
            .export_events()
            .expect("read hosted events after query"),
        events_before
    );
    assert!(store
        .list_instances()
        .expect("read hosted runtime instances")
        .is_empty());
}

#[test]
fn review_plan_cli_never_initializes_missing_authority_and_rejects_policy_flags() {
    let fixture = Fixture::new();
    let (planning, runtime_host) = host(&fixture);
    let out = admission::whip(
        &fixture,
        &["review", "plan", "witness", "attempt"],
        Some((&planning, &runtime_host)),
    );
    assert!(!out.status.success());
    for file in [
        "branches.sqlite",
        "content.sqlite",
        "items.sqlite",
        "runtime.sqlite",
    ] {
        assert!(!fixture.root.join(file).exists(), "created {file}");
    }
    for args in [
        vec!["review"],
        vec!["review", "plan", "witness"],
        vec![
            "review", "plan", "witness", "attempt", "--policy", "trusted",
        ],
        vec!["review", "run", "witness", "attempt"],
        vec!["review", "plan", "--policy", "attempt"],
    ] {
        let out = admission::whip(&fixture, &args, Some((&planning, &runtime_host)));
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
