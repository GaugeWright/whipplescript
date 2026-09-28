//! A requirement whose subject names a declaration (norm-plane §9, C1): a
//! Rust function, resolved through the charter-pinned canonicalizer on the
//! native host, and unresolved on the hosted object, which carries path
//! identity only.
//!
//! Support is still staged and selected by the requirement's domain, so what
//! the declaration subject changes is whether the requirement binds at a cut,
//! not what invalidates its support: an edit to another function in the same
//! file invalidates it too, because the tested artifact changed.

use super::admission::whip;
use super::*;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_custody::client::UnixSocketTransport;
use whipplescript_host_do::do_store::test_support::RusqliteDoSql;
use whipplescript_host_do::do_store::DoSqliteStore;
use whipplescript_host_do::norm_commands::execute_hosted_norm_command_with_artifacts;
use whipplescript_kernel::norm_custody::{NormCustodyKey, NormCustodyVersion};
use whipplescript_kernel::norm_execution::{fixtures as execution, PreparedNormExecution};
use whipplescript_kernel::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
use whipplescript_store::branches::MAINLINE_BRANCH_ID;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::NormCharter;
use whipplescript_store::norm_artifact::ArtifactLimits;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::vcs::{DeclCanonicalizer, NativeWorkspaceVcs};
use whipplescript_store::{ScriptCapabilityRegistration, SqliteStore};

const LIB: &str = "crates/policy/src/lib.rs";
const SUBJECT: &str = "crates/policy/src/lib.rs#fn crates/policy::grant_allows";
/// The version the charter pinned before this host's grammar bump.
const OLD_PIN: &str = "whipplescript.canon.rust/0 tree-sitter-rust/0.23";

/// Each cut of the mainline: the check's module, then the policy file as
/// written, with another function edited, with the subject's body edited,
/// and with the subject removed.
const CUTS: [(&str, &str, &str); 5] = [
    ("c0", "main.py", "def allow(user): return False"),
    (
        "c1",
        LIB,
        "pub fn grant_allows(grant: &str) -> bool {\n    grant == \"allow\"\n}\n\npub fn deny() -> bool {\n    false\n}\n",
    ),
    (
        "c2",
        LIB,
        "pub fn grant_allows(grant: &str) -> bool {\n    grant == \"allow\"\n}\n\npub fn deny() -> bool {\n    !true\n}\n",
    ),
    (
        "c3",
        LIB,
        "pub fn grant_allows(grant: &str) -> bool {\n    grant != \"deny\"\n}\n\npub fn deny() -> bool {\n    false\n}\n",
    ),
    ("c4", LIB, "pub fn deny() -> bool {\n    false\n}\n"),
];

/// One impact entry's work for the requirement.
fn work(planned: &Output, requirement: &str) -> String {
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned: Value = serde_json::from_slice(&planned.stdout).expect("impact JSON");
    let planned = if planned.get("plan").is_some() {
        planned
    } else {
        planned["result"].clone()
    };
    let impacts = planned["plan"]["requirements"][requirement]
        .as_array()
        .unwrap_or_else(|| panic!("{requirement} has no impact in {planned}"));
    assert_eq!(impacts.len(), 1, "{planned}");
    impacts[0]["work"]["kind"]
        .as_str()
        .expect("work kind")
        .to_owned()
}

/// A resource inventory answer's binding and gaps for the requirement.
fn bound(answer: &Value, requirement: &str) -> (bool, Vec<Value>) {
    let resources = &answer["result"]["resources"];
    let binding = &resources["bindings"][requirement];
    assert_eq!(binding["subject"], SUBJECT, "{answer}");
    assert!(
        binding["resources"]
            .as_array()
            .expect("domain resources")
            .contains(&json!(LIB)),
        "the domain binding stays whatever the subject resolves to: {answer}"
    );
    let gaps = resources["gaps"]
        .as_array()
        .expect("gaps")
        .iter()
        .filter(|gap| gap["requirement"] == requirement)
        .map(|gap| gap["reason"].clone())
        .collect();
    (
        binding["subject_present"].as_bool().expect("presence"),
        gaps,
    )
}

#[test]
fn a_declaration_subject_binds_through_the_pinned_canonicalizer_and_repins_by_activation() {
    let fixture = Fixture::new();
    let installed_version = whipplescript_canon::RustItems
        .version()
        .expect("the Rust canonicalizer is versioned")
        .to_owned();
    assert_ne!(installed_version, OLD_PIN);

    // The workspace, on the native host and on a hosted object, before the
    // gate leases either mainline.
    let mut vcs = NativeWorkspaceVcs::open(
        fixture.root.join("branches.sqlite"),
        fixture.root.join("content.sqlite"),
    )
    .expect("workspace");
    vcs.init("t0").expect("init");
    let hosted = RusqliteDoSql::with_store_schema();
    let hosted_vcs = || {
        whipplescript_host_do::do_branches::compose_vcs_shared(&hosted).expect("hosted workspace")
    };
    hosted_vcs().init("t0").expect("hosted mainline");
    for (cut, path, body) in CUTS {
        vcs.write(MAINLINE_BRANCH_ID, path, Some(body), cut, "t1")
            .expect("native write");
        hosted_vcs()
            .write(MAINLINE_BRANCH_ID, path, Some(body), cut, "t1")
            .expect("hosted write");
    }

    // C0 pins `.rs` to the version before the bump.
    let mut charter = NormCharter::bundled().expect("charter");
    let observation = execution::observation_vocabulary();
    let reference = |entry: &whipplescript_store::norm::NormVocabulary| {
        Vocabulary::new(entry.definition.clone())
            .expect("definition")
            .reference()
            .clone()
    };
    let observation_ref = reference(&observation);
    let requirement_ref = reference(
        charter
            .vocabularies
            .iter()
            .find(|entry| entry.definition.name == "obligation")
            .expect("obligation"),
    );
    charter.vocabularies.push(observation);
    charter.owner_scopes.push("observe.publish".into());
    charter.canonicalizers = [("rs".to_owned(), OLD_PIN.to_owned())].into();
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
    fixture.write(
        "fields.json",
        &json!({"name":"grant","proposition":"unknown denied","domain":"workspace","subject":SUBJECT,"support_contract":support.to_string()}),
    );
    let requirement = fixture.run(&[
        "create",
        "obligation@1",
        "--as",
        "owner",
        "--fields",
        "fields.json",
    ])["result"]["event_id"]
        .as_str()
        .expect("requirement")
        .to_owned();
    fixture.run(&["transition", &requirement, "accepted", "--as", "owner"]);

    // The host: an installed observer and the protected runtime.
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
    let planning = json!({"capability":"observer","roles":[{"vocabulary":requirement_ref,"interpretation":"context"},{"vocabulary":observation_ref,"interpretation":"published_execution"}]});
    let host_path = fixture.root.join("host.json");
    let host = Some((&planning, host_path.as_path()));
    let impact = |before: &str, after: &str| {
        work(
            &whip(&fixture, &["--json", "norm", "impact", before, after], host),
            &requirement,
        )
    };

    // Passing evidence for c1, through the verified execution and
    // publication path.
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
    let view = ledger.norm_view(&verifier).expect("view");
    let history = CapturedNormHistory::capture(
        &view,
        &ledger.export_events().expect("events"),
        &verifier,
        NormHistoryLimits::default(),
    )
    .expect("history");
    let artifact = vcs
        .capture_norm_artifact("c1", ArtifactLimits::default())
        .expect("c1");
    let prepared = PreparedNormExecution::prepare(
        &history,
        &verifier,
        &artifact,
        &installed,
        execution::selection(&view.ledger, &requirement),
    )
    .expect("prepared");
    drop(execution::journal_execution(
        SqliteStore::open(&runtime_path).expect("runtime"),
        &prepared,
        &execution::receipt(&prepared, false, false),
        false,
    ));
    drop(vcs);
    let published = whip(
        &fixture,
        &[
            "--json",
            "norm",
            "publish-observation",
            "instance",
            "run",
            "local-observation@1",
            "--as",
            "owner",
        ],
        None,
    );
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );

    // Under the old pin the host's canonicalizer disagrees: the subject is
    // unresolved, never resolved by its file's path, so the passing
    // evidence supports nothing.
    let (present, gaps) = bound(&fixture.run(&["resources", "c1"]), &requirement);
    assert!(!present);
    assert_eq!(
        gaps,
        vec![
            json!({"kind":"canonicalizer_mismatch","class":"rs","pinned":OLD_PIN,"installed":installed_version})
        ]
    );
    assert_eq!(impact("c1", "c1"), "resource_gap");

    // The recorded act: C1 re-pins `.rs` to the installed version.
    let mut repinned = charter.clone();
    repinned.canonicalizers = [("rs".to_owned(), installed_version.clone())].into();
    let migration: Vec<Value> = charter
        .vocabularies
        .iter()
        .map(|entry| json!({"from": reference(entry), "plan": {"plan": "retain"}}))
        .collect();
    fixture.write(
        "repin.json",
        &json!({"charter": repinned, "migration": migration}),
    );
    fixture.run(&["activate", "--as", "owner", "--proposal", "repin.json"]);

    // Pinned and present: the function binds, and c1's evidence supports it.
    let (present, gaps) = bound(&fixture.run(&["resources", "c1"]), &requirement);
    assert!(present);
    assert!(gaps.is_empty(), "{gaps:?}");
    assert_eq!(impact("c1", "c1"), "supported");
    // Editing the function's body invalidates that support: the tested
    // artifact changed, so it wants a fresh check.
    assert_eq!(impact("c1", "c3"), "check");
    // So does editing another function in the same file. The subject decides
    // whether the requirement binds, not what its run read: that is still
    // the domain, which changed.
    let (present, gaps) = bound(&fixture.run(&["resources", "c2"]), &requirement);
    assert!(present && gaps.is_empty(), "{gaps:?}");
    assert_eq!(impact("c1", "c2"), "check");
    // Removing the function leaves its file present and the subject missing.
    let (present, gaps) = bound(&fixture.run(&["resources", "c4"]), &requirement);
    assert!(!present);
    assert_eq!(gaps, vec![json!({"kind":"missing_subject"})]);
    assert_eq!(impact("c1", "c4"), "resource_gap");

    // The hosted object has no Rust canonicalizer, so it carries path
    // identity only: under the same pinned charter the subject is
    // unresolved there, naming what it lacks, where the native host binds it.
    let (checkpoint, events) = {
        let ledger = WorkItemStore::open(fixture.root.join("items.sqlite")).expect("ledger");
        (
            ledger
                .norm_checkpoint()
                .expect("checkpoint")
                .expect("pinned"),
            ledger.export_events().expect("events"),
        )
    };
    let mut store = DoSqliteStore::new(hosted.clone());
    store
        .pin_norm_checkpoint(&checkpoint)
        .expect("independent host pin");
    let public_bindings: Vec<Value> = [("owner", 1u8), ("worker", 2u8)]
        .into_iter()
        .map(|(name, seed)| {
            use ring::signature::KeyPair as _;
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
    let trust =
        json!({"bindings":[],"public_bindings":public_bindings,"creation_grants":[]}).to_string();
    let lease_sql = hosted.clone();
    let mut lease = |declared: &[String]| {
        whipplescript_store::branches::lease_gated_refs(
            &mut whipplescript_host_do::do_branches::DoBranches::new(lease_sql.clone())?,
            declared,
            "hosted-import",
        )
    };
    execute_hosted_norm_command_with_artifacts(
        &mut store,
        &trust,
        &json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"import","events":events}}).to_string(),
        None,
        Some(&mut lease),
        None,
        None,
    )
    .expect("the object admits the history");
    let capture = |cut: &str| hosted_vcs().capture_norm_artifact(cut, ArtifactLimits::default());
    let answer = execute_hosted_norm_command_with_artifacts(
        &mut store,
        &trust,
        &json!({"protocol":"whipplescript.norm.commands/v1","command":{"kind":"resources","point":{"cut":"c1"}}}).to_string(),
        Some(&capture),
        None,
        None,
        None,
    )
    .expect("the hosted inventory answers");
    let (present, gaps) = bound(
        &serde_json::from_str(&answer).expect("resources JSON"),
        &requirement,
    );
    assert!(!present);
    assert_eq!(
        gaps,
        vec![json!({"kind":"missing_canonicalizer","class":"rs"})]
    );
}
