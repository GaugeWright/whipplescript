//! A real Buck2 daemon building through the endpoint (DR-0124 §14.4): the
//! fixture project under its remote-only execution platform, every action
//! sent to the endpoint, its result classified as the platform says and
//! recorded as executed by the endpoint's own runner. Ignored by default: it
//! needs `buck2` on the PATH and is run by the bar's `buck2-test-executor`
//! section, which names the remedy where Buck2 is absent.

use std::path::Path;
use std::sync::Arc;

use whipplescript_remote_execution::endpoint::Endpoint;
use whipplescript_remote_execution::runner::LocalRunner;
use whipplescript_remote_execution::store::Principal;

fn copy_tree(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).expect("the fixture project") {
        let entry = entry.expect("the fixture's own step");
        let name = entry.file_name();
        if name == "buck-out" {
            continue;
        }
        let target = to.join(&name);
        if entry.path().is_dir() {
            std::fs::create_dir_all(&target).expect("the fixture's own step");
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("the fixture's own step");
        }
    }
}

#[tokio::test]
#[ignore = "needs buck2 on the PATH; the bar's buck2-test-executor section runs it"]
async fn buck2_builds_the_fixture_through_the_endpoint() {
    let scratch = tempfile::tempdir().expect("scratch");
    let project = scratch.path().join("project");
    std::fs::create_dir_all(&project).expect("the fixture's own step");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join("buck2-tests"),
        &project,
    );
    let mut endpoint = Endpoint::new(Arc::new(LocalRunner::new(scratch.path().join("actions"))));
    let (handle, _) = endpoint
        .admit(Principal {
            name: "owner".into(),
            labels: ["fixture".to_owned()].into_iter().collect(),
        })
        .expect("the fixture's own step");
    endpoint
        .serve_daemon_as(handle)
        .expect("the fixture's own step");
    let endpoint = Arc::new(endpoint);
    let (listener, address) = whipplescript_remote_execution::server::bind("127.0.0.1:0")
        .await
        .expect("the fixture's own step");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(whipplescript_remote_execution::server::serve(
        endpoint.clone(),
        listener,
        async move {
            let _ = stopped.await;
        },
    ));
    std::fs::write(
        project.join(".buckconfig.local"),
        format!(
            "[build]\nexecution_platforms = root//:remote\n\n[buck2_re_client]\nengine_address = grpc://{address}\naction_cache_address = grpc://{address}\ncas_address = grpc://{address}\ntls = false\ninstance_name = main\n\n[buck2]\ndigest_algorithms = SHA256\n"
        ),
    )
    .expect("the fixture's own step");
    let buck2 = |args: &[&str]| {
        let mut command = tokio::process::Command::new("buck2");
        command
            .current_dir(&project)
            .arg("--isolation-dir")
            .arg("whip-re")
            .args(args)
            .stdin(std::process::Stdio::null());
        command
    };
    let built = buck2(&["build", "//secret-gate:shout", "--show-full-json-output"])
        .output()
        .await
        .expect("buck2 runs");
    assert!(
        built.status.success(),
        "buck2 build failed:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let outputs: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&built.stdout).expect("an output map");
    let output = std::fs::read_to_string(&outputs["root//secret-gate:shout"]).expect("the output");
    let source = std::fs::read_to_string(project.join("secret-gate/FIXTURE"))
        .expect("the fixture's own step");
    assert_eq!(output, source.to_uppercase());
    // The action ran at the endpoint, once, classified as the platform says.
    let executed = endpoint.cache.executed_actions();
    assert_eq!(executed.len(), 1, "{executed:?}");
    let entry = &executed[0].1;
    assert!(entry.classification.labels.contains("fixture"));
    assert!(entry
        .classification
        .platform
        .iter()
        .any(|(name, value)| name == "whipplescript.labels" && value == "fixture"));
    assert_eq!(entry.result.exit_code, 0);
    // A second build is answered from the endpoint's cache, not rerun.
    let again = buck2(&["build", "//secret-gate:shout"])
        .output()
        .await
        .expect("the fixture's own step");
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(endpoint.cache.executed_actions().len(), 1);
    let killed = buck2(&["kill"])
        .output()
        .await
        .expect("the fixture's own step");
    assert!(killed.status.success());
    let _ = stop.send(());
    server
        .await
        .expect("the fixture's own step")
        .expect("the fixture's own step");
}
