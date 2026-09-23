//! The Home's build-engine wrapper (DR-0124 §14.1, §14.2) against a real
//! Buck2 over a cut recorded from `examples/buck2-tests`. Ignored by default:
//! it needs `buck2` on the PATH and is run by the bar's `buck2-test-executor`
//! section, which names the remedy where Buck2 is absent.

use super::*;
use crate::build_commands::{
    admit_trigger, artifact, artifact_records, artifact_vocabulary, build_target,
    classification_of, correspondence_fields, materialize_cut, materialize_projection,
    publish_correspondence, record_and_publish, scoped_result, test_targets, CutTree,
    HOME_ISOLATION_DIR, ORGANIZATION_CEILING,
};
use crate::build_scope::{LabelPolicy, Principal, Region, PACKAGE_CEILING};
use whipplescript_core::norm_buck2_report::{CaseStatus, Listing};
use whipplescript_kernel::norm_artifact_publication::INPUT_ROOT_ENCODING_V1;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::{
    NormAct, NormActor, NormCharter, NormStatement, NormVerifier, SignedNormEvent,
};

/// A fixture signer: the signature is the SHA-256 of the signing bytes.
struct Sha256Signer;

impl NormVerifier for Sha256Signer {
    fn verify(&self, _: &NormActor, signing_bytes: &[u8], signature: &str) -> Result<(), String> {
        if signature == sha256_hex(signing_bytes) {
            Ok(())
        } else {
            Err("bad fixture signature".into())
        }
    }
    fn authorize_creation(&self, _: &str, _: &NormActor) -> Result<(), String> {
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn the_fixture_signer_refuses_a_signature_that_is_not_the_digest() {
    assert_eq!(
        Sha256Signer.verify(&owner(), b"bytes", &sha256_hex(b"bytes")),
        Ok(())
    );
    assert_eq!(
        Sha256Signer.verify(&owner(), b"bytes", "not the digest"),
        Err("bad fixture signature".to_owned())
    );
}

fn owner() -> NormActor {
    NormActor {
        principal: "owner".into(),
        algorithm: "fixture".into(),
        key_id: "owner-key".into(),
    }
}

fn signed(nonce: &str, action: NormAct) -> SignedNormEvent {
    let statement = NormStatement {
        protocol: "whipplescript.norm/v1".into(),
        actor: owner(),
        nonce: nonce.into(),
        created_at: "2026-09-22T00:00:00Z".into(),
        action,
        premises: None,
    };
    let signature = sha256_hex(&statement.signing_bytes().expect("signing bytes"));
    SignedNormEvent {
        statement,
        signature,
        successor_signature: None,
    }
}

/// The fixture project recorded as a cut on a fresh vcs, the engineering
/// charter bootstrapped as the ledger, and the executor named for the daemon.
struct Fixture {
    _scratch: tempfile::TempDir,
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    vcs: whipplescript_store::vcs::NativeWorkspaceVcs,
    cut: String,
    items: WorkItemStore,
    ledger: String,
    journal: whipplescript_store::SqliteStore,
    executor: std::path::PathBuf,
    build_root: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let previous: Vec<(&str, Option<std::ffi::OsString>)> = [
            "WHIPPLESCRIPT_BRANCH_STORE",
            "WHIPPLESCRIPT_VCS_CONTENT_STORE",
            "WHIPPLESCRIPT_TEST_EXECUTOR",
        ]
        .into_iter()
        .map(|key| (key, std::env::var_os(key)))
        .collect();
        std::env::set_var(
            "WHIPPLESCRIPT_BRANCH_STORE",
            scratch.path().join("branches.sqlite"),
        );
        std::env::set_var(
            "WHIPPLESCRIPT_VCS_CONTENT_STORE",
            scratch.path().join("content.sqlite"),
        );
        // The executor built into the same target directory as this test binary
        // (target/debug/deps/whip-<hash> sits one level below it).
        let executor = std::env::current_exe()
            .expect("this test binary")
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the target profile directory")
            .join("whip-test-executor");
        assert!(executor.is_file(), "no executor at {}", executor.display());
        std::env::set_var("WHIPPLESCRIPT_TEST_EXECUTOR", &executor);

        // The cut: the fixture project, recorded file by file on the mainline.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join("buck2-tests");
        let mut vcs = open_vcs().expect("vcs");
        vcs.init("t0").expect("init");
        let mut cut = String::new();
        for (index, relative) in [
            ".buckconfig",
            ".buckroot",
            ".buck2-version",
            "FIXTURE",
            "rules.bzl",
            "platforms.bzl",
            "tests/passing.sh",
            "tests/swallowed.sh",
            "tests/silent.sh",
            "secret-gate/FIXTURE",
            "secret-gate/protected/flag",
        ]
        .iter()
        .enumerate()
        {
            let body = std::fs::read_to_string(fixture.join(relative)).expect(relative);
            cut = format!("fixture-{index}");
            vcs.write("main", relative, Some(&body), &cut, "t1")
                .expect("record the fixture file");
        }

        // The ledger: the engineering charter, which declares artifact,
        // build.publish and correspondence.
        let charter: NormCharter = serde_json::from_str(include_str!(
            "../../../../../examples/engineering/charter.json"
        ))
        .expect("the engineering charter");
        let mut items = WorkItemStore::open_in_memory().expect("items");
        let ledger = items
            .append_norm_event(
                &signed(
                    "engineering",
                    NormAct::Bootstrap {
                        creator: "owner".into(),
                        charter,
                    },
                ),
                &Sha256Signer,
            )
            .expect("bootstrap");
        let journal = whipplescript_store::SqliteStore::open_in_memory().expect("journal");
        let build_root = scratch.path().join("build");
        Self {
            _scratch: scratch,
            previous,
            vcs,
            cut,
            items,
            ledger,
            journal,
            executor,
            build_root,
        }
    }

    /// Build a target in the tree and publish its record with the basis given.
    fn publish(
        &mut self,
        tree: &CutTree,
        label: &str,
        basis: &str,
    ) -> (String, Vec<(String, String)>) {
        let built = build_target(tree, label).expect("buck2 builds the target");
        let view = self.items.norm_view(&Sha256Signer).expect("view");
        let vocabulary = artifact_vocabulary(&view).expect("the charter declares artifact");
        let record = artifact(tree, &built, &self.ledger, basis);
        let published = record_and_publish(
            &self.journal,
            &mut self.items,
            &Sha256Signer,
            &record,
            &vocabulary,
            Some(&view.authority_head),
            &owner(),
            "2026-09-22T00:00:00Z",
            |statement| {
                Ok(sha256_hex(
                    &statement.signing_bytes().expect("signing bytes"),
                ))
            },
        )
        .expect("the artifact publishes");
        (published.event_id, built.outputs)
    }

    fn stop(&self, tree: &CutTree) {
        let stopped = crate::build_commands::buck2(tree)
            .arg("kill")
            .output()
            .expect("kill");
        assert!(stopped.status.success());
    }

    fn restore(self) {
        for (key, value) in self.previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[test]
#[ignore = "needs buck2 on the PATH; the bar's buck2-test-executor section runs it"]
fn the_home_daemon_builds_a_cut_publishes_its_artifact_and_runs_its_tests() {
    let _guard = crate::env_lock();
    let mut fixture = Fixture::new();
    let cut = fixture.cut.clone();
    let ledger = fixture.ledger.clone();
    let executor = fixture.executor.clone();
    let build_root = fixture.build_root.clone();
    let vcs = &fixture.vcs;
    let journal = &fixture.journal;

    // Materialize the cut for the Home's daemon and build a target in it.
    let tree = materialize_cut(
        vcs,
        &cut,
        &build_root,
        &crate::build_commands::buck2_binary(),
    )
    .expect("the cut materializes");
    assert!(tree.root.join("FIXTURE").is_file());
    assert_eq!(tree.pin.as_deref(), Some("2026-09-15"));
    assert!(
        tree.buck2_version.starts_with("buck2 "),
        "{}",
        tree.buck2_version
    );
    let built = build_target(&tree, "//:passing").expect("buck2 builds the target");
    assert_eq!(built.label, "root//:passing");
    assert_eq!(built.outputs.len(), 1);
    assert_eq!(built.outputs[0].1.len(), 64);
    let items = &mut fixture.items;
    let view = items.norm_view(&Sha256Signer).expect("view");
    let vocabulary = artifact_vocabulary(&view).expect("the charter declares artifact");
    let record = artifact(&tree, &built, &ledger, ORGANIZATION_CEILING);
    assert_eq!(record.encoding, INPUT_ROOT_ENCODING_V1);
    assert_eq!(record.projection, None);
    let published = record_and_publish(
        journal,
        items,
        &Sha256Signer,
        &record,
        &vocabulary,
        Some(&view.authority_head),
        &owner(),
        "2026-09-22T00:00:00Z",
        |statement| {
            Ok(sha256_hex(
                &statement.signing_bytes().expect("signing bytes"),
            ))
        },
    )
    .expect("the artifact publishes");
    let after = items.norm_view(&Sha256Signer).expect("view");
    let artifact_record = &after.records[&published.event_id];
    assert_eq!(artifact_record.vocabulary.name, "artifact");
    assert_eq!(artifact_record.fields["cut"], serde_json::json!(cut));
    assert_eq!(
        artifact_record.fields["label"],
        serde_json::json!("root//:passing")
    );
    assert_eq!(
        artifact_record.fields["classification"],
        serde_json::json!(ORGANIZATION_CEILING)
    );
    // Publishing the same build again recovers the same record: at most once.
    let again = record_and_publish(
        journal,
        items,
        &Sha256Signer,
        &record,
        &vocabulary,
        Some(&view.authority_head),
        &owner(),
        "2026-09-22T00:00:00Z",
        |_| Err("a retained envelope is never re-signed".into()),
    )
    .expect("the retry recovers");
    assert_eq!(again.event_id, published.event_id);
    assert_eq!(again.build_record, published.build_record);

    // The tests, through the executor the daemon is configured to call.
    let report_path = build_root.join("report.json");
    let (status, report) = test_targets(&tree, &["//...".to_owned()], &executor, &report_path, 60)
        .expect("buck2 test runs through the executor");
    assert!(!status.success(), "the swallowed failure fails the run");
    assert_eq!(report.cut.as_deref(), Some(cut.as_str()));
    assert_eq!(report.exit_code, 32);
    let suite = |name: &str| {
        report
            .suites
            .iter()
            .find(|suite| suite.target.target == name)
            .unwrap_or_else(|| panic!("suite {name}"))
    };
    assert!(matches!(&suite("passing").listing, Listing::Listed { cases, .. } if cases.len() == 2));
    assert!(suite("swallowed")
        .executions
        .iter()
        .any(|execution| execution.case == "rejects_stale_grant"
            && execution.status == CaseStatus::Fail
            && execution.exit_code == Some(0)));
    assert_eq!(suite("silent").executions[0].status, CaseStatus::Unknown);

    // The Home's daemon, not the developer's: stop it by its isolation dir.
    assert_eq!(tree.isolation_dir, HOME_ISOLATION_DIR);
    fixture.stop(&tree);
    fixture.restore();
}

/// BE-03 and BE-04: the labeled action graph at the wrapper, under the
/// package ceiling. `dev` holds no label; `owner` holds `protected`, the
/// label of `secret-gate/protected/`, whose listing decides what
/// `//secret-gate:gate` produces without being an input of it.
#[test]
#[ignore = "needs buck2 on the PATH; the bar's buck2-test-executor section runs it"]
fn principals_reach_the_daemon_through_scoped_interfaces_and_the_tiers_correspond() {
    let _guard = crate::env_lock();
    let mut fixture = Fixture::new();
    let cut = fixture.cut.clone();
    let build_root = fixture.build_root.clone();
    let buck2 = crate::build_commands::buck2_binary();
    let policy = LabelPolicy::new(vec![Region {
        prefix: "secret-gate/protected/".into(),
        label: "protected".into(),
    }])
    .expect("a policy");
    let named = |name: &str, labels: &[&str]| Principal {
        name: name.into(),
        labels: labels.iter().map(|l| l.to_string()).collect(),
    };
    let dev = named("dev", &[]);
    let owner_principal = named("owner", &["protected"]);
    let owner = &owner_principal;
    let content = |outputs: &[(String, String)]| {
        std::fs::read_to_string(&outputs[0].0).expect("the output is readable")
    };

    // BE-03, the ungated tier: dev's projection lacks the protected region and
    // says so — the region is unobserved, never absent — and the build over it
    // takes the other branch of the glob. Its record claims the projection.
    let projected = materialize_projection(&fixture.vcs, &cut, &build_root, &buck2, &policy, &dev)
        .expect("the projection materializes");
    let projection = projected.projection.clone().expect("a projection");
    assert!(!projected.root.join("secret-gate/protected").exists());
    assert!(projected.root.join("secret-gate/FIXTURE").is_file());
    assert_eq!(
        projection.unobserved,
        vec!["secret-gate/protected/".to_owned()]
    );
    let over_projection = classification_of(&projected, "//secret-gate:gate", &policy)
        .expect("the projection classifies");
    assert!(over_projection.labels.is_empty(), "{over_projection:?}");
    admit_trigger(&dev, "//secret-gate:gate", &over_projection).expect("dev builds their own view");
    let (dev_gate, outputs) =
        fixture.publish(&projected, "//secret-gate:gate", &over_projection.basis());
    assert_eq!(content(&outputs), "without the protected observation");
    let view = fixture.items.norm_view(&Sha256Signer).expect("view");
    assert_eq!(
        view.records[&dev_gate].fields["projection"],
        serde_json::json!(projection.id)
    );
    assert_eq!(
        view.records[&dev_gate].fields["cut"],
        serde_json::json!(cut)
    );

    // BE-04, the gated tier: through the Home's daemon the same target is
    // classified by the observation that shaped it, refused to dev by name,
    // and built for owner with the account of what influenced it.
    let home =
        materialize_cut(&fixture.vcs, &cut, &build_root, &buck2).expect("the cut materializes");
    let gate = classification_of(&home, "//secret-gate:gate", &policy).expect("the cut classifies");
    assert_eq!(gate.basis(), format!("{PACKAGE_CEILING}:protected"));
    let listing = gate
        .influences
        .iter()
        .find(|influence| influence.kind == "package-listing")
        .expect("the package listing is an influence");
    assert_eq!(listing.subject, "root//secret-gate:gate//secret-gate");
    assert!(gate
        .influences
        .iter()
        .any(|i| i.kind == "include" && i.subject == "rules.bzl"));
    assert!(
        !gate.influences.iter().any(|i| i.kind == "input"),
        "{gate:?}"
    );
    assert_eq!(
        admit_trigger(&dev, "//secret-gate:gate", &gate).unwrap_err(),
        "//secret-gate:gate is classified package-ceiling/v1:protected, which dev does not hold: refused, not absent"
    );
    admit_trigger(owner, "//secret-gate:gate", &gate).expect("owner holds protected");
    let (owner_gate, outputs) = fixture.publish(&home, "//secret-gate:gate", &gate.basis());
    assert_eq!(content(&outputs), "with the protected observation");
    // An unrelated result of the same cut stays readable: the root package's
    // listing stops at the sub-package, and its inputs are public.
    let passing = classification_of(&home, "//:passing", &policy).expect("classifies");
    assert_eq!(passing.basis(), format!("{PACKAGE_CEILING}:"));
    assert!(passing
        .influences
        .iter()
        .any(|i| i.kind == "input" && i.subject == "tests/passing.sh"));
    admit_trigger(&dev, "//:passing", &passing).expect("public is dev's to trigger");
    let (cut_passing, _) = fixture.publish(&home, "//:passing", &passing.basis());

    // The result interface: dev reads the cut's public result and does not
    // observe the gated one; owner reads both.
    let view = fixture.items.norm_view(&Sha256Signer).expect("view");
    let gated = artifact_records(&view, &cut, "root//secret-gate:gate", None);
    assert_eq!(gated.len(), 1);
    assert_eq!(gated[0].id, owner_gate);
    assert_eq!(scoped_result(gated[0], &policy, &dev).unwrap(), None);
    assert!(scoped_result(gated[0], &policy, owner).unwrap().is_some());
    let public = artifact_records(&view, &cut, "root//:passing", None);
    let seen = scoped_result(public[0], &policy, &dev)
        .unwrap()
        .expect("dev reads the public result");
    assert_eq!(seen.record, cut_passing);

    // The two tiers as a checked correspondence: dev iterates //:passing over
    // the projection, the wrapper finds its outputs equal to the cut's, and
    // the correspondence binds both revisions as premises.
    let over_projection = classification_of(&projected, "//:passing", &policy).expect("classifies");
    let (dev_passing, _) = fixture.publish(&projected, "//:passing", &over_projection.basis());
    let view = fixture.items.norm_view(&Sha256Signer).expect("view");
    let projected_seen = scoped_result(
        artifact_records(&view, &cut, "root//:passing", Some(&projection.id))[0],
        &policy,
        &dev,
    )
    .unwrap()
    .expect("dev reads their own result");
    assert_eq!(projected_seen.record, dev_passing);
    assert_eq!(projected_seen.outputs, seen.outputs);
    let fields = correspondence_fields("root//:passing", &projected_seen, &seen, &projection, &cut)
        .expect("equal outputs correspond");
    let correspondence = publish_correspondence(
        &mut fixture.items,
        &Sha256Signer,
        &view,
        &fields,
        vec![projected_seen.revision.clone(), seen.revision.clone()],
        &self::owner(),
        "2026-09-22T00:00:00Z",
        |statement| {
            Ok(sha256_hex(
                &statement.signing_bytes().expect("signing bytes"),
            ))
        },
    )
    .expect("the checked correspondence is admitted");
    let view = fixture.items.norm_view(&Sha256Signer).expect("view");
    let record = &view.records[&correspondence];
    assert_eq!(record.vocabulary.name, "correspondence");
    assert_eq!(record.fields["mode"], serde_json::json!("checked"));
    assert_eq!(record.fields["sources"], serde_json::json!([dev_passing]));
    assert_eq!(record.fields["targets"], serde_json::json!([cut_passing]));
    // The gated target's projected result has nothing to correspond to under
    // dev's view: the cut's result is unobserved, and no correspondence can
    // be checked against what the view does not hold.
    let dev_gate_seen = scoped_result(&view.records[&dev_gate], &policy, &dev)
        .unwrap()
        .expect("dev reads their own projected result");
    assert!(
        artifact_records(&view, &cut, "root//secret-gate:gate", None)
            .into_iter()
            .all(|record| scoped_result(record, &policy, &dev).unwrap().is_none())
    );
    assert_ne!(
        dev_gate_seen.outputs,
        scoped_result(gated[0], &policy, owner)
            .unwrap()
            .unwrap()
            .outputs
    );

    fixture.stop(&projected);
    fixture.stop(&home);
    fixture.restore();
}
