//! The Home's build-engine wrapper (DR-0124 §14.1, first half) against a real
//! Buck2 over a cut recorded from `examples/buck2-tests`. Ignored by default:
//! it needs `buck2` on the PATH and is run by the bar's `buck2-test-executor`
//! section, which names the remedy where Buck2 is absent.

use super::*;
use crate::build_commands::{
    artifact, artifact_vocabulary, build_target, materialize_cut, record_and_publish, test_targets,
    HOME_ISOLATION_DIR, ORGANIZATION_CEILING,
};
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

#[test]
#[ignore = "needs buck2 on the PATH; the bar's buck2-test-executor section runs it"]
fn the_home_daemon_builds_a_cut_publishes_its_artifact_and_runs_its_tests() {
    let _guard = crate::env_lock();
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
        "tests/passing.sh",
        "tests/swallowed.sh",
        "tests/silent.sh",
    ]
    .iter()
    .enumerate()
    {
        let body = std::fs::read_to_string(fixture.join(relative)).expect(relative);
        cut = format!("fixture-{index}");
        vcs.write("main", relative, Some(&body), &cut, "t1")
            .expect("record the fixture file");
    }

    // The ledger: the engineering charter, which declares artifact and build.publish.
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

    // Materialize the cut for the Home's daemon and build a target in it.
    let build_root = scratch.path().join("build");
    let tree = materialize_cut(
        &vcs,
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
    let view = items.norm_view(&Sha256Signer).expect("view");
    let vocabulary = artifact_vocabulary(&view).expect("the charter declares artifact");
    let record = artifact(&tree, &built, &ledger, ORGANIZATION_CEILING);
    assert_eq!(record.encoding, INPUT_ROOT_ENCODING_V1);
    let published = record_and_publish(
        &journal,
        &mut items,
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
        &journal,
        &mut items,
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
    let report_path = scratch.path().join("report.json");
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
    let stopped = crate::build_commands::buck2(&tree)
        .arg("kill")
        .output()
        .expect("kill");
    assert!(stopped.status.success());
    let _ = HOME_ISOLATION_DIR;
    for (key, value) in previous {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
}
